/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE FILE UTILITIES IMPLEMENTATION
 * ============================================================================
 *
 * @file FileUtils.c
 * @brief Enterprise-grade file operations for kernel-mode EDR/XDR.
 *
 * Implements enterprise-grade class file handling with:
 * - Safe file information retrieval with proper IRQL handling
 * - Normalized path acquisition (NT/DOS path conversion)
 * - File attribute and metadata extraction
 * - Alternate Data Stream (ADS) detection
 * - File type identification (PE, script, archive, document)
 * - Secure file reading with size limits
 * - Volume information retrieval
 * - Reparse point and symbolic link handling
 * - Zone identifier extraction with actual content parsing
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

#include "FileUtils.h"
#include "StringUtils.h"
#include "MemoryUtils.h"

// ============================================================================
// ALLOC_PRAGMA - Page alignment for functions
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeInitializeFileUtils)
#pragma alloc_text(PAGE, ShadowStrikeCleanupFileUtils)
#pragma alloc_text(PAGE, ShadowStrikeGetFileName)
#pragma alloc_text(PAGE, ShadowStrikeGetFileNameFromFileObject)
#pragma alloc_text(PAGE, ShadowStrikeGetShortFileName)
#pragma alloc_text(PAGE, ShadowStrikeGetFileId)
#pragma alloc_text(PAGE, ShadowStrikeGetFileId128)
#pragma alloc_text(PAGE, ShadowStrikeGetVolumeSerial)
#pragma alloc_text(PAGE, ShadowStrikeGetFileSize)
#pragma alloc_text(PAGE, ShadowStrikeGetFileAttributes)
#pragma alloc_text(PAGE, ShadowStrikeGetFileInfo)
#pragma alloc_text(PAGE, ShadowStrikeGetFileBasicInfo)
#pragma alloc_text(PAGE, ShadowStrikeGetFileStandardInfo)
#pragma alloc_text(PAGE, ShadowStrikeDetectFileType)
#pragma alloc_text(PAGE, ShadowStrikeIsFilePE)
#pragma alloc_text(PAGE, ShadowStrikeHasAlternateDataStreams)
#pragma alloc_text(PAGE, ShadowStrikeGetZoneIdentifier)
#pragma alloc_text(PAGE, ShadowStrikeGetVolumeInfo)
#pragma alloc_text(PAGE, ShadowStrikeGetVolumeType)
#pragma alloc_text(PAGE, ShadowStrikeIsNetworkVolume)
#pragma alloc_text(PAGE, ShadowStrikeIsRemovableVolume)
#pragma alloc_text(PAGE, ShadowStrikeReadFileHeader)
#pragma alloc_text(PAGE, ShadowStrikeReadFileAtOffset)
#pragma alloc_text(PAGE, ShadowStrikeInitFileReadContext)
#pragma alloc_text(PAGE, ShadowStrikeReadNextChunk)
#pragma alloc_text(PAGE, ShadowStrikeIsReparsePoint)
#pragma alloc_text(PAGE, ShadowStrikeIsSymbolicLink)
#pragma alloc_text(PAGE, ShadowStrikeGetReparseTarget)
#pragma alloc_text(PAGE, ShadowStrikeGetFileOwner)
#pragma alloc_text(PAGE, ShadowStrikeIsDirectory)
#pragma alloc_text(PAGE, ShadowStrikeFreeFileName)
#pragma alloc_text(PAGE, ShadowStrikeCleanupFileReadContext)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

/**
 * @brief PE Optional Header magic for 32-bit
 */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b

/**
 * @brief PE Optional Header magic for 64-bit
 */
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

/**
 * @brief PE DLL characteristics flag
 */
#define IMAGE_FILE_DLL 0x2000

/**
 * @brief Native subsystem (drivers)
 */
#define IMAGE_SUBSYSTEM_NATIVE 1

/**
 * @brief Symbolic link reparse tag
 */
#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000C
#endif

/**
 * @brief Mount point (junction) reparse tag
 */
#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
#endif

/**
 * @brief Maximum Zone.Identifier stream content size to read
 */
#define SHADOW_ZONE_ID_MAX_CONTENT_SIZE 1024

/**
 * @brief Allocation tag for stream buffers
 */
#define SHADOW_STREAM_TAG 'sSsS'

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief DOS header structure for PE detection
 */
#pragma pack(push, 1)
typedef struct _SHADOW_DOS_HEADER {
    USHORT e_magic;         // MZ signature
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;        // Offset to PE header
} SHADOW_DOS_HEADER, *PSHADOW_DOS_HEADER;

typedef struct _SHADOW_FILE_HEADER {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} SHADOW_FILE_HEADER, *PSHADOW_FILE_HEADER;

typedef struct _SHADOW_OPTIONAL_HEADER32 {
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONG  BaseOfData;
    ULONG  ImageBase;
    ULONG  SectionAlignment;
    ULONG  FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG  Win32VersionValue;
    ULONG  SizeOfImage;
    ULONG  SizeOfHeaders;
    ULONG  CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
} SHADOW_OPTIONAL_HEADER32, *PSHADOW_OPTIONAL_HEADER32;

typedef struct _SHADOW_OPTIONAL_HEADER64 {
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONGLONG ImageBase;
    ULONG  SectionAlignment;
    ULONG  FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG  Win32VersionValue;
    ULONG  SizeOfImage;
    ULONG  SizeOfHeaders;
    ULONG  CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
} SHADOW_OPTIONAL_HEADER64, *PSHADOW_OPTIONAL_HEADER64;

typedef struct _SHADOW_NT_HEADERS {
    ULONG Signature;
    SHADOW_FILE_HEADER FileHeader;
    // Optional header follows (32 or 64 bit)
} SHADOW_NT_HEADERS, *PSHADOW_NT_HEADERS;
#pragma pack(pop)

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief File utilities initialization state (0 = not init, 1 = init)
 */
static volatile LONG g_FileUtilsInitialized = 0;

/**
 * @brief Filter handle stored during initialization for FltCreateFileEx calls
 */
static PFLT_FILTER g_FileUtilsFilterHandle = NULL;

/**
 * @brief Lookaside list for file read buffers
 */
static NPAGED_LOOKASIDE_LIST g_FileBufferLookaside;

/**
 * @brief Lookaside list initialized flag (0 = not init, 1 = init)
 */
static volatile LONG g_LookasideInitialized = 0;

/**
 * @brief Rundown protection for lookaside list access.
 *        Prevents teardown while any thread is allocating/freeing from lookaside.
 */
static EX_RUNDOWN_REF g_LookasideRundown;

// ============================================================================
// EXTENSION TABLES
// ============================================================================

/**
 * @brief Executable file extensions
 */
static const PCWSTR g_ExecutableExtensions[] = {
    L".exe", L".dll", L".sys", L".scr", L".com", L".cpl",
    L".ocx", L".drv", L".efi", L".pif", L".msi", L".msix",
    L".appx", L".appxbundle", NULL
};

/**
 * @brief Script file extensions
 */
static const PCWSTR g_ScriptExtensions[] = {
    L".ps1", L".psm1", L".psd1", L".bat", L".cmd", L".vbs",
    L".vbe", L".js", L".jse", L".wsf", L".wsh", L".hta",
    L".py", L".pyw", L".pl", L".rb", L".sh", NULL
};

/**
 * @brief Archive file extensions
 */
static const PCWSTR g_ArchiveExtensions[] = {
    L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2",
    L".xz", L".cab", L".iso", L".img", L".arj", L".lzh",
    L".z", NULL
};

/**
 * @brief Document file extensions
 */
static const PCWSTR g_DocumentExtensions[] = {
    L".doc", L".docx", L".docm", L".xls", L".xlsx", L".xlsm",
    L".ppt", L".pptx", L".pptm", L".rtf", L".odt", L".ods",
    L".odp", L".pdf", NULL
};

// ============================================================================
// MAGIC BYTE SIGNATURES
// ============================================================================

/**
 * @brief File magic byte signatures for type detection
 */
typedef struct _SHADOW_FILE_SIGNATURE {
    const UCHAR* Magic;
    ULONG MagicLength;
    ULONG Offset;
    SHADOW_FILE_TYPE FileType;
} SHADOW_FILE_SIGNATURE;

static const UCHAR g_MagicPDF[] = { 0x25, 0x50, 0x44, 0x46 };          // %PDF
static const UCHAR g_MagicZIP[] = { 0x50, 0x4B, 0x03, 0x04 };          // PK..
static const UCHAR g_MagicRAR[] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }; // Rar!
static const UCHAR g_Magic7Z[] = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }; // 7z
static const UCHAR g_MagicGZ[] = { 0x1F, 0x8B };                        // gzip
static const UCHAR g_MagicLNK[] = { 0x4C, 0x00, 0x00, 0x00 };          // LNK
static const UCHAR g_MagicMSI[] = { 0xD0, 0xCF, 0x11, 0xE0 };          // OLE

static const SHADOW_FILE_SIGNATURE g_FileSignatures[] = {
    { g_MagicPDF, sizeof(g_MagicPDF), 0, ShadowFileTypePDF },
    { g_MagicRAR, sizeof(g_MagicRAR), 0, ShadowFileTypeArchive },
    { g_Magic7Z, sizeof(g_Magic7Z), 0, ShadowFileTypeArchive },
    { g_MagicGZ, sizeof(g_MagicGZ), 0, ShadowFileTypeArchive },
    { g_MagicLNK, sizeof(g_MagicLNK), 0, ShadowFileTypeShortcut },
    { g_MagicMSI, sizeof(g_MagicMSI), 0, ShadowFileTypeInstaller },
    { g_MagicZIP, sizeof(g_MagicZIP), 0, ShadowFileTypeArchive },
    { NULL, 0, 0, ShadowFileTypeUnknown }
};

// ============================================================================
// INTERNAL HELPER PROTOTYPES
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
static
NTSTATUS
ShadowpParseZoneIdentifierContent(
    _In_reads_bytes_(ContentSize) PUCHAR Content,
    _In_ ULONG ContentSize,
    _Out_ PUCHAR ZoneId
    );

_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
ShadowpValidateStreamInfo(
    _In_ PFILE_STREAM_INFORMATION StreamInfo,
    _In_ ULONG BufferSize,
    _In_ ULONG CurrentOffset
    );

_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
ShadowpValidateReparseBuffer(
    _In_ PREPARSE_DATA_BUFFER ReparseData,
    _In_ ULONG BufferSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
static
NTSTATUS
ShadowpParsePEHeaders(
    _In_reads_bytes_(BufferSize) const UCHAR* HeaderBuffer,
    _In_ ULONG BufferSize,
    _Out_ PBOOLEAN IsPE,
    _Out_opt_ PBOOLEAN Is64Bit,
    _Out_opt_ PBOOLEAN IsDLL,
    _Out_opt_ PBOOLEAN IsDriver,
    _Out_opt_ PUSHORT Subsystem,
    _Out_opt_ PUSHORT Characteristics,
    _Out_opt_ PULONG Timestamp,
    _Out_opt_ PULONG Checksum
    );

// ============================================================================
// INITIALIZATION / CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInitializeFileUtils(
    PFLT_FILTER FilterHandle
    )
{
    LONG previousValue;

    PAGED_CODE();

    if (FilterHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Thread-safe initialization using interlocked compare-exchange
    //
    previousValue = InterlockedCompareExchange(&g_FileUtilsInitialized, 1, 0);
    if (previousValue != 0) {
        //
        // Already initialized by another thread
        //
        return STATUS_SUCCESS;
    }

    g_FileUtilsFilterHandle = FilterHandle;

    //
    // Initialize rundown protection for lookaside list lifetime management
    //
    ExInitializeRundownProtection(&g_LookasideRundown);

    //
    // Initialize lookaside list for file read buffers
    //
    ExInitializeNPagedLookasideList(
        &g_FileBufferLookaside,
        NULL,                           // Allocate function
        NULL,                           // Free function
        POOL_NX_ALLOCATION,             // Flags
        SHADOW_FILE_READ_CHUNK_SIZE,    // Size
        SHADOW_FILEBUF_TAG,             // Tag
        0                               // Depth (0 = system default)
    );

    InterlockedExchange(&g_LookasideInitialized, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] FileUtils initialized successfully\n");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeCleanupFileUtils(
    VOID
    )
{
    LONG previousValue;

    PAGED_CODE();

    //
    // Thread-safe cleanup
    //
    previousValue = InterlockedCompareExchange(&g_FileUtilsInitialized, 0, 1);
    if (previousValue != 1) {
        //
        // Not initialized or already cleaned up
        //
        return;
    }

    if (InterlockedCompareExchange(&g_LookasideInitialized, 0, 1) == 1) {
        //
        // Wait for all in-flight lookaside allocations/frees to complete.
        // This prevents use-after-free if a thread is mid-operation.
        //
        ExWaitForRundownProtectionRelease(&g_LookasideRundown);
        ExDeleteNPagedLookasideList(&g_FileBufferLookaside);
    }

    g_FileUtilsFilterHandle = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] FileUtils cleaned up\n");
}

// ============================================================================
// FILE NAME OPERATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileName(
    PFLT_CALLBACK_DATA Data,
    PUNICODE_STRING FileName
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    SIZE_T allocationSize;

    PAGED_CODE();

    //
    // Initialize output
    //
    FileName->Buffer = NULL;
    FileName->Length = 0;
    FileName->MaximumLength = 0;

    //
    // Validate parameters
    //
    if (Data == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Try normalized name first (best for path comparisons)
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    //
    // Fallback to opened name if normalized fails
    //
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );

        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    //
    // Parse the name information
    //
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    //
    // Calculate allocation size with overflow check
    //
    allocationSize = (SIZE_T)nameInfo->Name.Length + sizeof(WCHAR);
    if (allocationSize < nameInfo->Name.Length ||
        allocationSize > SHADOW_MAX_PATH_BYTES ||
        allocationSize > MAXUSHORT) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_NAME_TOO_LONG;
    }

    //
    // Allocate buffer for output string
    //
    FileName->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
        allocationSize,
        SHADOW_FILEPATH_TAG
    );

    if (FileName->Buffer == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy the name
    //
    RtlCopyMemory(FileName->Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length);
    FileName->Buffer[nameInfo->Name.Length / sizeof(WCHAR)] = L'\0';
    FileName->Length = nameInfo->Name.Length;
    FileName->MaximumLength = (USHORT)allocationSize;

    FltReleaseFileNameInformation(nameInfo);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileNameFromFileObject(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PUNICODE_STRING FileName
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    SIZE_T allocationSize;

    PAGED_CODE();

    //
    // Initialize output
    //
    FileName->Buffer = NULL;
    FileName->Length = 0;
    FileName->MaximumLength = 0;

    //
    // Validate parameters
    //
    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Query name from file object
    //
    status = FltGetFileNameInformationUnsafe(
        FileObject,
        Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        //
        // Try opened name as fallback
        //
        status = FltGetFileNameInformationUnsafe(
            FileObject,
            Instance,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );

        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    //
    // Parse the name
    //
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    //
    // Calculate allocation size with overflow check
    //
    allocationSize = (SIZE_T)nameInfo->Name.Length + sizeof(WCHAR);
    if (allocationSize < nameInfo->Name.Length ||
        allocationSize > SHADOW_MAX_PATH_BYTES ||
        allocationSize > MAXUSHORT) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_NAME_TOO_LONG;
    }

    //
    // Allocate and copy
    //
    FileName->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
        allocationSize,
        SHADOW_FILEPATH_TAG
    );

    if (FileName->Buffer == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(FileName->Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length);
    FileName->Buffer[nameInfo->Name.Length / sizeof(WCHAR)] = L'\0';
    FileName->Length = nameInfo->Name.Length;
    FileName->MaximumLength = (USHORT)allocationSize;

    FltReleaseFileNameInformation(nameInfo);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeFreeFileName(
    PUNICODE_STRING FileName
    )
{
    if (FileName == NULL) {
        return;
    }

    if (FileName->Buffer != NULL) {
        ExFreePoolWithTag(FileName->Buffer, SHADOW_FILEPATH_TAG);
        FileName->Buffer = NULL;
    }

    FileName->Length = 0;
    FileName->MaximumLength = 0;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetShortFileName(
    PFLT_CALLBACK_DATA Data,
    PUNICODE_STRING ShortName
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    SIZE_T allocationSize;

    PAGED_CODE();

    //
    // Initialize output
    //
    ShortName->Buffer = NULL;
    ShortName->Length = 0;
    ShortName->MaximumLength = 0;

    if (Data == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get short name
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_SHORT | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    //
    // Check if short name exists
    //
    if (nameInfo->FinalComponent.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_NOT_FOUND;
    }

    allocationSize = (SIZE_T)nameInfo->FinalComponent.Length + sizeof(WCHAR);
    if (allocationSize < nameInfo->FinalComponent.Length ||
        allocationSize > MAXUSHORT) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_NAME_TOO_LONG;
    }

    ShortName->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
        allocationSize,
        SHADOW_FILEPATH_TAG
    );

    if (ShortName->Buffer == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(ShortName->Buffer, nameInfo->FinalComponent.Buffer,
                  nameInfo->FinalComponent.Length);
    ShortName->Buffer[nameInfo->FinalComponent.Length / sizeof(WCHAR)] = L'\0';
    ShortName->Length = nameInfo->FinalComponent.Length;
    ShortName->MaximumLength = (USHORT)allocationSize;

    FltReleaseFileNameInformation(nameInfo);

    return STATUS_SUCCESS;
}

// ============================================================================
// FILE IDENTIFICATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileId(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PULONG64 FileId
    )
{
    NTSTATUS status;
    FILE_INTERNAL_INFORMATION internalInfo;
    ULONG returnLength;

    PAGED_CODE();

    *FileId = 0;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &internalInfo,
        sizeof(FILE_INTERNAL_INFORMATION),
        FileInternalInformation,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        *FileId = internalInfo.IndexNumber.QuadPart;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileId128(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PFILE_ID_128 FileId128
    )
{
    NTSTATUS status;
    FILE_ID_INFORMATION idInfo;
    ULONG returnLength;

    PAGED_CODE();

    RtlZeroMemory(FileId128, sizeof(FILE_ID_128));

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &idInfo,
        sizeof(FILE_ID_INFORMATION),
        FileIdInformation,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        RtlCopyMemory(FileId128, &idInfo.FileId, sizeof(FILE_ID_128));
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetVolumeSerial(
    PFLT_INSTANCE Instance,
    PULONG VolumeSerial
    )
{
    NTSTATUS status;
    union {
        FILE_FS_VOLUME_INFORMATION VolumeInfo;
        UCHAR Buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 64 * sizeof(WCHAR)];
    } volumeBuffer;

    PAGED_CODE();

    *VolumeSerial = 0;

    if (Instance == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Query volume information directly using FltQueryVolumeInformation
    // This gives us the actual volume serial number
    //
    RtlZeroMemory(&volumeBuffer, sizeof(volumeBuffer));

    status = FltQueryVolumeInformation(
        Instance,
        NULL,
        &volumeBuffer.VolumeInfo,
        sizeof(volumeBuffer),
        FileFsVolumeInformation
    );

    if (NT_SUCCESS(status)) {
        *VolumeSerial = volumeBuffer.VolumeInfo.VolumeSerialNumber;
    }

    return status;
}

// ============================================================================
// FILE SIZE AND ATTRIBUTES
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileSize(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PLONGLONG FileSize
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION standardInfo;
    ULONG returnLength;

    PAGED_CODE();

    *FileSize = 0;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &standardInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        *FileSize = standardInfo.EndOfFile.QuadPart;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileAttributes(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PULONG FileAttributes
    )
{
    NTSTATUS status;
    FILE_BASIC_INFORMATION basicInfo;
    ULONG returnLength;

    PAGED_CODE();

    *FileAttributes = 0;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &basicInfo,
        sizeof(FILE_BASIC_INFORMATION),
        FileBasicInformation,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        *FileAttributes = basicInfo.FileAttributes;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileBasicInfo(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PFILE_BASIC_INFORMATION BasicInfo
    )
{
    ULONG returnLength;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || BasicInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(BasicInfo, sizeof(FILE_BASIC_INFORMATION));

    return FltQueryInformationFile(
        Instance,
        FileObject,
        BasicInfo,
        sizeof(FILE_BASIC_INFORMATION),
        FileBasicInformation,
        &returnLength
    );
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileStandardInfo(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PFILE_STANDARD_INFORMATION StandardInfo
    )
{
    ULONG returnLength;

    PAGED_CODE();

    if (Instance == NULL || FileObject == NULL || StandardInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(StandardInfo, sizeof(FILE_STANDARD_INFORMATION));

    return FltQueryInformationFile(
        Instance,
        FileObject,
        StandardInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation,
        &returnLength
    );
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileInfo(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PSHADOW_FILE_INFO FileInfo
    )
{
    NTSTATUS status;
    NTSTATUS basicStatus;
    NTSTATUS standardStatus;
    FILE_BASIC_INFORMATION basicInfo;
    FILE_STANDARD_INFORMATION standardInfo;
    FILE_INTERNAL_INFORMATION internalInfo;
    ULONG returnLength;

    PAGED_CODE();

    //
    // Initialize output
    //
    RtlZeroMemory(FileInfo, sizeof(SHADOW_FILE_INFO));

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Query basic information — this is the primary query
    //
    basicStatus = FltQueryInformationFile(
        Instance,
        FileObject,
        &basicInfo,
        sizeof(FILE_BASIC_INFORMATION),
        FileBasicInformation,
        &returnLength
    );

    if (NT_SUCCESS(basicStatus)) {
        FileInfo->FileAttributes = basicInfo.FileAttributes;
        FileInfo->CreationTime = basicInfo.CreationTime;
        FileInfo->LastAccessTime = basicInfo.LastAccessTime;
        FileInfo->LastWriteTime = basicInfo.LastWriteTime;
        FileInfo->ChangeTime = basicInfo.ChangeTime;

        FileInfo->IsDirectory = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
        FileInfo->IsReadOnly = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_READONLY);
        FileInfo->IsHidden = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_HIDDEN);
        FileInfo->IsSystem = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_SYSTEM);
        FileInfo->IsArchive = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_ARCHIVE);
        FileInfo->IsCompressed = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_COMPRESSED);
        FileInfo->IsEncrypted = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_ENCRYPTED);
        FileInfo->IsSparseFile = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_SPARSE_FILE);
        FileInfo->IsReparsePoint = BooleanFlagOn(basicInfo.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT);
    }

    //
    // Query standard information
    //
    standardStatus = FltQueryInformationFile(
        Instance,
        FileObject,
        &standardInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation,
        &returnLength
    );

    if (NT_SUCCESS(standardStatus)) {
        FileInfo->FileSize = standardInfo.EndOfFile.QuadPart;
        FileInfo->AllocationSize = standardInfo.AllocationSize.QuadPart;
        FileInfo->NumberOfLinks = standardInfo.NumberOfLinks;
        FileInfo->IsDirectory = FileInfo->IsDirectory || standardInfo.Directory;
    }

    //
    // If both primary queries failed, the file object is likely invalid
    //
    if (!NT_SUCCESS(basicStatus) && !NT_SUCCESS(standardStatus)) {
        return basicStatus;
    }

    //
    // Query file ID (non-critical — failure is acceptable)
    //
    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &internalInfo,
        sizeof(FILE_INTERNAL_INFORMATION),
        FileInternalInformation,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        FileInfo->FileId = internalInfo.IndexNumber.QuadPart;
    }

    //
    // Get volume serial (non-critical)
    //
    ShadowStrikeGetVolumeSerial(Instance, &FileInfo->VolumeSerial);

    //
    // Determine reparse point details (symlink vs junction)
    //
    if (FileInfo->IsReparsePoint) {
        ULONG reparseTag = 0;
        BOOLEAN isReparse = FALSE;

        if (NT_SUCCESS(ShadowStrikeIsReparsePoint(Instance, FileObject, &isReparse, &reparseTag))) {
            FileInfo->IsSymLink = (isReparse && reparseTag == IO_REPARSE_TAG_SYMLINK);
            FileInfo->IsJunction = (isReparse && reparseTag == IO_REPARSE_TAG_MOUNT_POINT);
        }
    }

    //
    // Skip content-based detection for directories or empty files
    //
    if (!FileInfo->IsDirectory && FileInfo->FileSize > 0) {
        PUCHAR headerBuffer = NULL;
        ULONG headerBytesRead = 0;

        //
        // Single header read for both magic detection and PE parsing.
        // Eliminates redundant I/O and TOCTOU window between reads.
        //
        headerBuffer = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_PAGED,
            SHADOW_PE_HEADER_READ_SIZE,
            SHADOW_FILEBUF_TAG
        );

        if (headerBuffer != NULL) {
            status = ShadowStrikeReadFileHeader(
                Instance,
                FileObject,
                headerBuffer,
                SHADOW_PE_HEADER_READ_SIZE,
                &headerBytesRead
            );

            if (NT_SUCCESS(status) && headerBytesRead >= 2) {
                const SHADOW_DOS_HEADER* dosHeader = (const SHADOW_DOS_HEADER*)headerBuffer;
                const SHADOW_FILE_SIGNATURE* sig;

                //
                // Check for PE via magic bytes and full header parse
                //
                if (headerBytesRead >= sizeof(SHADOW_DOS_HEADER) &&
                    dosHeader->e_magic == SHADOW_MZ_SIGNATURE) {

                    BOOLEAN isPE = FALSE;
                    BOOLEAN is64Bit = FALSE;
                    BOOLEAN isDLL = FALSE;
                    BOOLEAN isDriver = FALSE;
                    USHORT subsystem = 0;
                    USHORT characteristics = 0;
                    ULONG timestamp = 0;
                    ULONG checksum = 0;

                    ShadowpParsePEHeaders(
                        headerBuffer,
                        headerBytesRead,
                        &isPE,
                        &is64Bit,
                        &isDLL,
                        &isDriver,
                        &subsystem,
                        &characteristics,
                        &timestamp,
                        &checksum
                    );

                    FileInfo->IsPE = isPE;
                    FileInfo->Is64Bit = is64Bit;
                    FileInfo->IsDLL = isDLL;
                    FileInfo->IsDriver = isDriver;
                    FileInfo->PESubsystem = subsystem;
                    FileInfo->PECharacteristics = characteristics;
                    FileInfo->PETimestamp = timestamp;
                    FileInfo->PEChecksum = checksum;
                    FileInfo->IsExecutable = isPE;

                    if (isPE) {
                        if (isDriver) {
                            FileInfo->FileType = ShadowFileTypeDriver;
                        } else if (isDLL) {
                            FileInfo->FileType = ShadowFileTypeDLL;
                        } else {
                            FileInfo->FileType = is64Bit ? ShadowFileTypePE64 : ShadowFileTypePE32;
                        }
                    } else {
                        FileInfo->FileType = ShadowFileTypeData;
                    }
                } else {
                    //
                    // Not PE — check magic byte signatures
                    //
                    FileInfo->FileType = ShadowFileTypeData;
                    for (sig = g_FileSignatures; sig->Magic != NULL; sig++) {
                        if (headerBytesRead >= sig->Offset + sig->MagicLength) {
                            if (RtlCompareMemory(
                                    headerBuffer + sig->Offset,
                                    sig->Magic,
                                    sig->MagicLength) == sig->MagicLength) {
                                FileInfo->FileType = sig->FileType;
                                break;
                            }
                        }
                    }
                }
            }

            ExFreePoolWithTag(headerBuffer, SHADOW_FILEBUF_TAG);
        }

        //
        // Single stream query for both ADS detection and Zone.Identifier.
        // Eliminates the second FltQueryInformationFile(FileStreamInformation) call.
        //
        {
            PUCHAR streamBuffer = NULL;
            PFILE_STREAM_INFORMATION streamInfo;
            ULONG streamReturnLength;
            ULONG streamOffset = 0;
            ULONG streamCount = 0;
            BOOLEAN foundZoneStream = FALSE;
            const ULONG streamBufSize = 4096;
            UNICODE_STRING zoneIdStream;
            UNICODE_STRING streamName;

            RtlInitUnicodeString(&zoneIdStream, SHADOW_ZONE_IDENTIFIER_STREAM);

            streamBuffer = (PUCHAR)ExAllocatePool2(
                POOL_FLAG_PAGED,
                streamBufSize,
                SHADOW_STREAM_TAG
            );

            if (streamBuffer != NULL) {
                status = FltQueryInformationFile(
                    Instance,
                    FileObject,
                    streamBuffer,
                    streamBufSize,
                    FileStreamInformation,
                    &streamReturnLength
                );

                if (NT_SUCCESS(status)) {
                    streamInfo = (PFILE_STREAM_INFORMATION)streamBuffer;

                    while (streamOffset < streamReturnLength) {
                        if (!ShadowpValidateStreamInfo(streamInfo, streamReturnLength, streamOffset)) {
                            break;
                        }

                        streamCount++;

                        //
                        // Check for Zone.Identifier stream
                        //
                        streamName.Buffer = streamInfo->StreamName;
                        streamName.Length = (USHORT)min(streamInfo->StreamNameLength, MAXUSHORT);
                        streamName.MaximumLength = streamName.Length;

                        if (RtlEqualUnicodeString(&streamName, &zoneIdStream, TRUE)) {
                            foundZoneStream = TRUE;
                        }

                        if (streamInfo->NextEntryOffset == 0) {
                            break;
                        }

                        streamOffset += streamInfo->NextEntryOffset;
                        streamInfo = (PFILE_STREAM_INFORMATION)(streamBuffer + streamOffset);
                    }

                    FileInfo->HasADS = (streamCount > 1);
                }

                ExFreePoolWithTag(streamBuffer, SHADOW_STREAM_TAG);
            }

            //
            // If Zone.Identifier stream was found, read its content
            //
            if (foundZoneStream) {
                FileInfo->HasZoneId = TRUE;
                //
                // Attempt to read zone ID value. Use the dedicated function
                // which handles the stream open/read/parse sequence.
                //
                ShadowStrikeGetZoneIdentifier(
                    Instance,
                    FileObject,
                    &FileInfo->HasZoneId,
                    &FileInfo->ZoneId
                );
            }
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// FILE TYPE DETECTION
// ============================================================================

/**
 * @brief Internal helper to check extension against list
 */
static
BOOLEAN
ShadowpCheckExtensionList(
    _In_ PCUNICODE_STRING Extension,
    _In_ const PCWSTR* ExtensionList
    )
{
    UNICODE_STRING extToCheck;
    const PCWSTR* current;

    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return FALSE;
    }

    for (current = ExtensionList; *current != NULL; current++) {
        RtlInitUnicodeString(&extToCheck, *current);
        if (RtlEqualUnicodeString(Extension, &extToCheck, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeDetectFileType(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PSHADOW_FILE_TYPE FileType
    )
{
    NTSTATUS status;
    PUCHAR headerBuffer = NULL;
    ULONG bytesRead = 0;
    const SHADOW_FILE_SIGNATURE* sig;
    const SHADOW_DOS_HEADER* dosHeader;
    const ULONG headerSize = 256;

    PAGED_CODE();

    *FileType = ShadowFileTypeUnknown;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate header buffer from pool (avoid stack pressure in deep call chains)
    //
    headerBuffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        headerSize,
        SHADOW_FILEBUF_TAG
    );

    if (headerBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read file header
    //
    status = ShadowStrikeReadFileHeader(
        Instance,
        FileObject,
        headerBuffer,
        headerSize,
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead < 2) {
        ExFreePoolWithTag(headerBuffer, SHADOW_FILEBUF_TAG);
        return status;
    }

    //
    // Check for PE first (most common for security)
    //
    dosHeader = (const SHADOW_DOS_HEADER*)headerBuffer;
    if (bytesRead >= sizeof(SHADOW_DOS_HEADER) &&
        dosHeader->e_magic == SHADOW_MZ_SIGNATURE) {
        *FileType = ShadowFileTypePE32;
        ExFreePoolWithTag(headerBuffer, SHADOW_FILEBUF_TAG);
        return STATUS_SUCCESS;
    }

    //
    // Check against known magic signatures
    //
    for (sig = g_FileSignatures; sig->Magic != NULL; sig++) {
        if (bytesRead >= sig->Offset + sig->MagicLength) {
            if (RtlCompareMemory(
                    headerBuffer + sig->Offset,
                    sig->Magic,
                    sig->MagicLength) == sig->MagicLength) {
                *FileType = sig->FileType;
                ExFreePoolWithTag(headerBuffer, SHADOW_FILEBUF_TAG);
                return STATUS_SUCCESS;
            }
        }
    }

    //
    // Default to data file
    //
    *FileType = ShadowFileTypeData;

    ExFreePoolWithTag(headerBuffer, SHADOW_FILEBUF_TAG);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeDetectFileTypeByExtension(
    PCUNICODE_STRING FileName,
    PSHADOW_FILE_TYPE FileType
    )
{
    NTSTATUS status;
    UNICODE_STRING extension;

    *FileType = ShadowFileTypeUnknown;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Extract extension using StringUtils
    //
    status = ShadowStrikeGetFileExtension(FileName, &extension);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Check executable extensions with specific sub-classification
    //
    if (ShadowpCheckExtensionList(&extension, g_ExecutableExtensions)) {
        UNICODE_STRING dllExt, sysExt, drvExt, htaExt, msiExt, msixExt;

        RtlInitUnicodeString(&dllExt, L".dll");
        RtlInitUnicodeString(&sysExt, L".sys");
        RtlInitUnicodeString(&drvExt, L".drv");
        RtlInitUnicodeString(&htaExt, L".hta");
        RtlInitUnicodeString(&msiExt, L".msi");
        RtlInitUnicodeString(&msixExt, L".msix");

        if (RtlEqualUnicodeString(&extension, &dllExt, TRUE) ||
            RtlEqualUnicodeString(&extension, &sysExt, TRUE) ||
            RtlEqualUnicodeString(&extension, &drvExt, TRUE)) {
            //
            // These are PE types but need content-based refinement.
            // Extension alone cannot determine DLL vs Driver reliably.
            //
            if (RtlEqualUnicodeString(&extension, &sysExt, TRUE)) {
                *FileType = ShadowFileTypeDriver;
            } else if (RtlEqualUnicodeString(&extension, &dllExt, TRUE)) {
                *FileType = ShadowFileTypeDLL;
            } else {
                *FileType = ShadowFileTypePE32;
            }
        } else if (RtlEqualUnicodeString(&extension, &htaExt, TRUE)) {
            *FileType = ShadowFileTypeHtmlApp;
        } else if (RtlEqualUnicodeString(&extension, &msiExt, TRUE) ||
                   RtlEqualUnicodeString(&extension, &msixExt, TRUE)) {
            *FileType = ShadowFileTypeInstaller;
        } else {
            *FileType = ShadowFileTypePE32;
        }
        return STATUS_SUCCESS;
    }

    //
    // Check script extensions
    //
    if (ShadowpCheckExtensionList(&extension, g_ScriptExtensions)) {
        *FileType = ShadowFileTypeScript;
        return STATUS_SUCCESS;
    }

    //
    // Check archive extensions
    //
    if (ShadowpCheckExtensionList(&extension, g_ArchiveExtensions)) {
        *FileType = ShadowFileTypeArchive;
        return STATUS_SUCCESS;
    }

    //
    // Check document extensions
    //
    if (ShadowpCheckExtensionList(&extension, g_DocumentExtensions)) {
        UNICODE_STRING pdfExt;
        RtlInitUnicodeString(&pdfExt, L".pdf");
        if (RtlEqualUnicodeString(&extension, &pdfExt, TRUE)) {
            *FileType = ShadowFileTypePDF;
        } else {
            *FileType = ShadowFileTypeDocument;
        }
        return STATUS_SUCCESS;
    }

    *FileType = ShadowFileTypeData;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeIsFilePE(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PBOOLEAN IsPE,
    PBOOLEAN Is64Bit
    )
{
    NTSTATUS status;
    PUCHAR headerBuffer = NULL;
    ULONG bytesRead = 0;

    PAGED_CODE();

    *IsPE = FALSE;
    if (Is64Bit != NULL) {
        *Is64Bit = FALSE;
    }

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate header buffer from pool — 4KB is too large for kernel stack
    //
    headerBuffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        SHADOW_PE_HEADER_READ_SIZE,
        SHADOW_FILEBUF_TAG
    );

    if (headerBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Read PE header area
    //
    status = ShadowStrikeReadFileHeader(
        Instance,
        FileObject,
        headerBuffer,
        SHADOW_PE_HEADER_READ_SIZE,
        &bytesRead
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(headerBuffer, SHADOW_FILEBUF_TAG);
        return status;
    }

    //
    // Parse PE headers from buffer
    //
    status = ShadowpParsePEHeaders(
        headerBuffer,
        bytesRead,
        IsPE,
        Is64Bit,
        NULL,   // IsDLL
        NULL,   // IsDriver
        NULL,   // Subsystem
        NULL,   // Characteristics
        NULL,   // Timestamp
        NULL    // Checksum
    );

    ExFreePoolWithTag(headerBuffer, SHADOW_FILEBUF_TAG);
    return status;
}

/**
 * @brief Parse PE headers from an already-read buffer.
 *        Extracts all PE metadata with strict bounds checking.
 *        Returns STATUS_SUCCESS even if file is not PE (IsPE will be FALSE).
 */
static
NTSTATUS
ShadowpParsePEHeaders(
    _In_reads_bytes_(BufferSize) const UCHAR* HeaderBuffer,
    _In_ ULONG BufferSize,
    _Out_ PBOOLEAN IsPE,
    _Out_opt_ PBOOLEAN Is64Bit,
    _Out_opt_ PBOOLEAN IsDLL,
    _Out_opt_ PBOOLEAN IsDriver,
    _Out_opt_ PUSHORT Subsystem,
    _Out_opt_ PUSHORT Characteristics,
    _Out_opt_ PULONG Timestamp,
    _Out_opt_ PULONG Checksum
    )
{
    const SHADOW_DOS_HEADER* dosHeader;
    const SHADOW_NT_HEADERS* ntHeaders;
    LONG peOffset;
    ULONG optHeaderOffset;
    USHORT magic;

    *IsPE = FALSE;
    if (Is64Bit != NULL) *Is64Bit = FALSE;
    if (IsDLL != NULL) *IsDLL = FALSE;
    if (IsDriver != NULL) *IsDriver = FALSE;
    if (Subsystem != NULL) *Subsystem = 0;
    if (Characteristics != NULL) *Characteristics = 0;
    if (Timestamp != NULL) *Timestamp = 0;
    if (Checksum != NULL) *Checksum = 0;

    //
    // Need at least DOS header
    //
    if (BufferSize < sizeof(SHADOW_DOS_HEADER)) {
        return STATUS_SUCCESS;
    }

    dosHeader = (const SHADOW_DOS_HEADER*)HeaderBuffer;

    if (dosHeader->e_magic != SHADOW_MZ_SIGNATURE) {
        return STATUS_SUCCESS;
    }

    //
    // Validate PE offset — must be positive and >= DOS header size
    //
    peOffset = dosHeader->e_lfanew;
    if (peOffset < (LONG)sizeof(SHADOW_DOS_HEADER) || peOffset < 0) {
        return STATUS_SUCCESS;
    }

    //
    // Ensure NT headers fit in buffer
    //
    if ((ULONG)peOffset + sizeof(SHADOW_NT_HEADERS) > BufferSize) {
        return STATUS_SUCCESS;
    }

    ntHeaders = (const SHADOW_NT_HEADERS*)(HeaderBuffer + peOffset);
    if (ntHeaders->Signature != SHADOW_PE_SIGNATURE) {
        return STATUS_SUCCESS;
    }

    //
    // Valid PE file
    //
    *IsPE = TRUE;

    //
    // Extract COFF header fields
    //
    if (Characteristics != NULL) {
        *Characteristics = ntHeaders->FileHeader.Characteristics;
    }
    if (Timestamp != NULL) {
        *Timestamp = ntHeaders->FileHeader.TimeDateStamp;
    }
    if (IsDLL != NULL) {
        *IsDLL = BooleanFlagOn(ntHeaders->FileHeader.Characteristics, IMAGE_FILE_DLL);
    }

    //
    // Parse optional header for bitness, subsystem, checksum
    //
    optHeaderOffset = (ULONG)peOffset + sizeof(ULONG) + sizeof(SHADOW_FILE_HEADER);

    if (optHeaderOffset + sizeof(USHORT) > BufferSize) {
        return STATUS_SUCCESS;
    }

    magic = *(const USHORT*)(HeaderBuffer + optHeaderOffset);

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (Is64Bit != NULL) *Is64Bit = TRUE;

        //
        // Parse 64-bit optional header fields
        //
        if (optHeaderOffset + sizeof(SHADOW_OPTIONAL_HEADER64) <= BufferSize) {
            const SHADOW_OPTIONAL_HEADER64* opt64 =
                (const SHADOW_OPTIONAL_HEADER64*)(HeaderBuffer + optHeaderOffset);

            if (Subsystem != NULL) *Subsystem = opt64->Subsystem;
            if (Checksum != NULL) *Checksum = opt64->CheckSum;
            if (IsDriver != NULL) {
                *IsDriver = (opt64->Subsystem == IMAGE_SUBSYSTEM_NATIVE);
            }
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (Is64Bit != NULL) *Is64Bit = FALSE;

        //
        // Parse 32-bit optional header fields
        //
        if (optHeaderOffset + sizeof(SHADOW_OPTIONAL_HEADER32) <= BufferSize) {
            const SHADOW_OPTIONAL_HEADER32* opt32 =
                (const SHADOW_OPTIONAL_HEADER32*)(HeaderBuffer + optHeaderOffset);

            if (Subsystem != NULL) *Subsystem = opt32->Subsystem;
            if (Checksum != NULL) *Checksum = opt32->CheckSum;
            if (IsDriver != NULL) {
                *IsDriver = (opt32->Subsystem == IMAGE_SUBSYSTEM_NATIVE);
            }
        }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsExecutableExtension(
    PCUNICODE_STRING FileName
    )
{
    UNICODE_STRING extension;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    if (!NT_SUCCESS(ShadowStrikeGetFileExtension(FileName, &extension))) {
        return FALSE;
    }

    return ShadowpCheckExtensionList(&extension, g_ExecutableExtensions);
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsScriptExtension(
    PCUNICODE_STRING FileName
    )
{
    UNICODE_STRING extension;

    if (FileName == NULL || FileName->Buffer == NULL) {
        return FALSE;
    }

    if (!NT_SUCCESS(ShadowStrikeGetFileExtension(FileName, &extension))) {
        return FALSE;
    }

    return ShadowpCheckExtensionList(&extension, g_ScriptExtensions);
}

// ============================================================================
// ALTERNATE DATA STREAMS (ADS)
// ============================================================================

/**
 * @brief Validate stream information entry within buffer bounds
 */
static
BOOLEAN
ShadowpValidateStreamInfo(
    _In_ PFILE_STREAM_INFORMATION StreamInfo,
    _In_ ULONG BufferSize,
    _In_ ULONG CurrentOffset
    )
{
    ULONG minRequired;

    //
    // Check that the structure header fits
    //
    minRequired = FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName);
    if (CurrentOffset + minRequired > BufferSize) {
        return FALSE;
    }

    //
    // Check that stream name fits within buffer
    //
    if (StreamInfo->StreamNameLength > BufferSize - CurrentOffset - minRequired) {
        return FALSE;
    }

    //
    // Verify NextEntryOffset doesn't go backwards or overflow
    //
    if (StreamInfo->NextEntryOffset != 0) {
        if (StreamInfo->NextEntryOffset < minRequired + StreamInfo->StreamNameLength) {
            return FALSE;  // Overlapping entries
        }
        if (CurrentOffset + StreamInfo->NextEntryOffset < CurrentOffset) {
            return FALSE;  // Integer overflow
        }
        if (CurrentOffset + StreamInfo->NextEntryOffset >= BufferSize) {
            return FALSE;  // Beyond buffer
        }
    }

    return TRUE;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeHasAlternateDataStreams(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PBOOLEAN HasADS
    )
{
    NTSTATUS status;
    PUCHAR buffer = NULL;
    PFILE_STREAM_INFORMATION streamInfo;
    ULONG returnLength;
    ULONG streamCount = 0;
    ULONG currentOffset = 0;
    const ULONG bufferSize = 4096;

    PAGED_CODE();

    *HasADS = FALSE;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate buffer from pool instead of stack
    //
    buffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        bufferSize,
        SHADOW_STREAM_TAG
    );

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = FltQueryInformationFile(
        Instance,
        FileObject,
        buffer,
        bufferSize,
        FileStreamInformation,
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        //
        // Some file systems don't support streams
        //
        ExFreePoolWithTag(buffer, SHADOW_STREAM_TAG);
        if (status == STATUS_INVALID_PARAMETER ||
            status == STATUS_NOT_IMPLEMENTED) {
            return STATUS_SUCCESS;
        }
        return status;
    }

    //
    // Count streams with proper bounds checking
    //
    currentOffset = 0;
    streamInfo = (PFILE_STREAM_INFORMATION)buffer;

    while (currentOffset < returnLength) {
        //
        // Validate this entry before accessing it
        //
        if (!ShadowpValidateStreamInfo(streamInfo, returnLength, currentOffset)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Invalid stream info at offset %u\n", currentOffset);
            break;
        }

        streamCount++;

        if (streamInfo->NextEntryOffset == 0) {
            break;
        }

        currentOffset += streamInfo->NextEntryOffset;
        streamInfo = (PFILE_STREAM_INFORMATION)(buffer + currentOffset);
    }

    ExFreePoolWithTag(buffer, SHADOW_STREAM_TAG);

    //
    // More than one stream means ADS present
    // (First stream is always the default $DATA stream)
    //
    *HasADS = (streamCount > 1);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsAlternateDataStream(
    PCUNICODE_STRING FileName
    )
{
    USHORT i;
    USHORT lengthChars;
    USHORT fileNameStart = 0;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    lengthChars = FileName->Length / sizeof(WCHAR);

    //
    // Find the last backslash to isolate the file name component.
    // This correctly handles NT paths (\Device\HarddiskVolumeN\...),
    // UNC paths (\\server\share\...), and DOS paths (C:\...).
    // Only search for ':' within the filename, not the directory path.
    //
    for (i = 0; i < lengthChars; i++) {
        if (FileName->Buffer[i] == L'\\') {
            fileNameStart = i + 1;
        }
    }

    //
    // Search for colon within the filename component only
    //
    for (i = fileNameStart; i < lengthChars; i++) {
        if (FileName->Buffer[i] == L':') {
            //
            // Any colon in the filename component indicates an ADS
            //
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Parse Zone.Identifier stream content to extract ZoneId value
 *
 * Format is:
 * [ZoneTransfer]
 * ZoneId=3
 *
 * Zone values:
 * 0 = Local machine
 * 1 = Local intranet
 * 2 = Trusted sites
 * 3 = Internet
 * 4 = Restricted sites
 */
static
NTSTATUS
ShadowpParseZoneIdentifierContent(
    _In_reads_bytes_(ContentSize) PUCHAR Content,
    _In_ ULONG ContentSize,
    _Out_ PUCHAR ZoneId
    )
{
    ULONG i;
    ULONG searchLimit;
    BOOLEAN foundZoneId = FALSE;
    UCHAR zoneValue = 0;

    //
    // SECURITY: Initialize output parameter first (defense in depth)
    //
    *ZoneId = 0;

    //
    // SECURITY: Validate input parameters
    //
    if (Content == NULL || ContentSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // SECURITY FIX: Prevent integer underflow
    // "ZoneId=X" requires minimum 8 bytes (7 for prefix + 1 for digit)
    // Without this check, ContentSize < 8 would cause unsigned underflow
    // in the loop condition, leading to buffer over-read (CVE-class bug)
    //
    #define ZONE_ID_PREFIX_LEN  7   // strlen("ZoneId=")
    #define ZONE_ID_MIN_LEN     8   // "ZoneId=" + at least one digit

    if (ContentSize < ZONE_ID_MIN_LEN) {
        //
        // Content too small to contain a valid ZoneId entry
        //
        return STATUS_NOT_FOUND;
    }

    //
    // SECURITY: Calculate safe search limit to prevent buffer over-read
    // We need at least 8 bytes from position i: "ZoneId=X"
    // So the last valid starting position is ContentSize - 8
    //
    searchLimit = ContentSize - ZONE_ID_PREFIX_LEN;

    //
    // Search for "ZoneId=" in content
    // Content is typically UTF-8 or ASCII from Zone.Identifier ADS
    //
    for (i = 0; i < searchLimit; i++) {
        if (RtlCompareMemory(Content + i, "ZoneId=", ZONE_ID_PREFIX_LEN) == ZONE_ID_PREFIX_LEN) {
            //
            // Found ZoneId= prefix, now parse the digit
            // SECURITY: Bounds check is guaranteed by searchLimit calculation
            //
            UCHAR digit = Content[i + ZONE_ID_PREFIX_LEN];

            //
            // Valid Zone IDs per Windows Security Zones:
            // 0 = Local Machine (most trusted)
            // 1 = Local Intranet
            // 2 = Trusted Sites
            // 3 = Internet
            // 4 = Restricted Sites (least trusted)
            //
            if (digit >= '0' && digit <= '4') {
                zoneValue = digit - '0';
                foundZoneId = TRUE;
                break;
            }
            //
            // Invalid digit - continue searching in case of malformed content
            // with multiple ZoneId entries (defense against evasion)
            //
        }
    }

    #undef ZONE_ID_PREFIX_LEN
    #undef ZONE_ID_MIN_LEN

    if (foundZoneId) {
        *ZoneId = zoneValue;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetZoneIdentifier(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PBOOLEAN HasZoneId,
    PUCHAR ZoneId
    )
{
    NTSTATUS status;
    PUCHAR buffer = NULL;
    PFILE_STREAM_INFORMATION streamInfo;
    ULONG returnLength;
    UNICODE_STRING zoneIdStream;
    UNICODE_STRING streamName;
    ULONG currentOffset = 0;
    BOOLEAN foundStream = FALSE;
    const ULONG bufferSize = 4096;

    PAGED_CODE();

    *HasZoneId = FALSE;
    *ZoneId = 0;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&zoneIdStream, SHADOW_ZONE_IDENTIFIER_STREAM);

    //
    // Allocate buffer from pool
    //
    buffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        bufferSize,
        SHADOW_STREAM_TAG
    );

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = FltQueryInformationFile(
        Instance,
        FileObject,
        buffer,
        bufferSize,
        FileStreamInformation,
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, SHADOW_STREAM_TAG);
        if (status == STATUS_INVALID_PARAMETER ||
            status == STATUS_NOT_IMPLEMENTED) {
            return STATUS_SUCCESS;
        }
        return status;
    }

    //
    // Search for Zone.Identifier stream with bounds checking
    //
    currentOffset = 0;
    streamInfo = (PFILE_STREAM_INFORMATION)buffer;

    while (currentOffset < returnLength) {
        if (!ShadowpValidateStreamInfo(streamInfo, returnLength, currentOffset)) {
            break;
        }

        streamName.Buffer = streamInfo->StreamName;
        streamName.Length = (USHORT)min(streamInfo->StreamNameLength, MAXUSHORT);
        streamName.MaximumLength = streamName.Length;

        if (RtlEqualUnicodeString(&streamName, &zoneIdStream, TRUE)) {
            foundStream = TRUE;
            break;
        }

        if (streamInfo->NextEntryOffset == 0) {
            break;
        }

        currentOffset += streamInfo->NextEntryOffset;
        streamInfo = (PFILE_STREAM_INFORMATION)(buffer + currentOffset);
    }

    ExFreePoolWithTag(buffer, SHADOW_STREAM_TAG);

    if (!foundStream) {
        //
        // No Zone.Identifier stream — file has no Mark-of-the-Web.
        // Do NOT default to zone 3 here; the stream genuinely does not exist.
        //
        return STATUS_SUCCESS;
    }

    //
    // Zone.Identifier stream exists — read its content to extract zone value
    //
    *HasZoneId = TRUE;

    {
        UNICODE_STRING fileName;
        UNICODE_STRING adsPath;
        OBJECT_ATTRIBUTES objAttrs;
        IO_STATUS_BLOCK ioStatus;
        HANDLE streamHandle = NULL;
        PFILE_OBJECT streamFileObject = NULL;
        PUCHAR streamContent = NULL;
        ULONG bytesRead = 0;
        SIZE_T totalPathSize;
        const ULONG streamContentSize = SHADOW_ZONE_ID_MAX_CONTENT_SIZE;

        status = ShadowStrikeGetFileNameFromFileObject(Instance, FileObject, &fileName);
        if (!NT_SUCCESS(status)) {
            //
            // Stream exists but we can't build the path to read it.
            // Default to zone 3 (Internet) as conservative assumption.
            //
            *ZoneId = 3;
            return STATUS_SUCCESS;
        }

        //
        // Build ADS path: filename + :Zone.Identifier
        // Use SIZE_T arithmetic to prevent USHORT overflow (CRITICAL-03 fix)
        //
        totalPathSize = (SIZE_T)fileName.Length +
                        (sizeof(SHADOW_ZONE_IDENTIFIER_STREAM) - sizeof(WCHAR));

        if (totalPathSize > MAXUSHORT || totalPathSize > SHADOW_MAX_PATH_BYTES) {
            ShadowStrikeFreeFileName(&fileName);
            *ZoneId = 3;
            return STATUS_SUCCESS;
        }

        adsPath.MaximumLength = (USHORT)totalPathSize + sizeof(WCHAR);
        adsPath.Buffer = (PWCH)ExAllocatePool2(
            POOL_FLAG_PAGED,
            adsPath.MaximumLength,
            SHADOW_FILEPATH_TAG
        );

        if (adsPath.Buffer == NULL) {
            ShadowStrikeFreeFileName(&fileName);
            *ZoneId = 3;
            return STATUS_SUCCESS;
        }

        RtlCopyMemory(adsPath.Buffer, fileName.Buffer, fileName.Length);
        RtlCopyMemory(
            (PUCHAR)adsPath.Buffer + fileName.Length,
            SHADOW_ZONE_IDENTIFIER_STREAM,
            sizeof(SHADOW_ZONE_IDENTIFIER_STREAM) - sizeof(WCHAR)
        );
        adsPath.Length = (USHORT)totalPathSize;

        ShadowStrikeFreeFileName(&fileName);

        //
        // Open the Zone.Identifier stream using the stored filter handle
        //
        if (g_FileUtilsFilterHandle == NULL) {
            ExFreePoolWithTag(adsPath.Buffer, SHADOW_FILEPATH_TAG);
            *ZoneId = 3;
            return STATUS_SUCCESS;
        }

        InitializeObjectAttributes(
            &objAttrs,
            &adsPath,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            NULL,
            NULL
        );

        status = FltCreateFileEx(
            g_FileUtilsFilterHandle,
            Instance,
            &streamHandle,
            &streamFileObject,
            FILE_GENERIC_READ,
            &objAttrs,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0,
            IO_IGNORE_SHARE_ACCESS_CHECK
        );

        ExFreePoolWithTag(adsPath.Buffer, SHADOW_FILEPATH_TAG);

        if (!NT_SUCCESS(status)) {
            //
            // Stream exists but we can't open it — default to zone 3
            //
            *ZoneId = 3;
            return STATUS_SUCCESS;
        }

        //
        // Allocate buffer and read stream content
        //
        streamContent = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_PAGED,
            streamContentSize,
            SHADOW_STREAM_TAG
        );

        if (streamContent != NULL) {
            LARGE_INTEGER offset;
            offset.QuadPart = 0;

            status = FltReadFile(
                Instance,
                streamFileObject,
                &offset,
                streamContentSize - 1,
                streamContent,
                FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                &bytesRead,
                NULL,
                NULL
            );

            if ((NT_SUCCESS(status) || status == STATUS_END_OF_FILE) &&
                bytesRead > 0) {
                streamContent[bytesRead] = '\0';

                status = ShadowpParseZoneIdentifierContent(
                    streamContent,
                    bytesRead,
                    ZoneId
                );

                if (!NT_SUCCESS(status)) {
                    *ZoneId = 3;
                }
            } else {
                *ZoneId = 3;
            }

            ExFreePoolWithTag(streamContent, SHADOW_STREAM_TAG);
        } else {
            *ZoneId = 3;
        }

        //
        // Cleanup — close handle before dereferencing file object
        //
        FltClose(streamHandle);
        ObDereferenceObject(streamFileObject);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// VOLUME OPERATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetVolumeInfo(
    PFLT_INSTANCE Instance,
    PSHADOW_VOLUME_INFO VolumeInfo
    )
{
    NTSTATUS status;
    PFLT_VOLUME volume = NULL;
    PFLT_VOLUME_PROPERTIES volumeProps = NULL;
    ULONG returnLength;
    const ULONG propsBufferSize = sizeof(FLT_VOLUME_PROPERTIES) + 512;

    PAGED_CODE();

    RtlZeroMemory(VolumeInfo, sizeof(SHADOW_VOLUME_INFO));

    if (Instance == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate volume properties buffer from pool
    //
    volumeProps = (PFLT_VOLUME_PROPERTIES)ExAllocatePool2(
        POOL_FLAG_PAGED,
        propsBufferSize,
        SHADOW_FILE_TAG
    );

    if (volumeProps == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Get volume from instance
    //
    status = FltGetVolumeFromInstance(Instance, &volume);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(volumeProps, SHADOW_FILE_TAG);
        return status;
    }

    //
    // Query volume properties
    //
    status = FltGetVolumeProperties(
        volume,
        volumeProps,
        propsBufferSize,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        //
        // Determine volume type from device type and characteristics
        //
        switch (volumeProps->DeviceType) {
            case FILE_DEVICE_NETWORK_FILE_SYSTEM:
            case FILE_DEVICE_DFS:
            case FILE_DEVICE_DFS_FILE_SYSTEM:
                VolumeInfo->VolumeType = ShadowVolumeNetwork;
                VolumeInfo->IsNetworkDrive = TRUE;
                break;

            case FILE_DEVICE_CD_ROM:
            case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
            case FILE_DEVICE_DVD:
                VolumeInfo->VolumeType = ShadowVolumeCDROM;
                break;

            case FILE_DEVICE_VIRTUAL_DISK:
                VolumeInfo->VolumeType = ShadowVolumeVirtual;
                break;

            case FILE_DEVICE_DISK:
            case FILE_DEVICE_DISK_FILE_SYSTEM:
            default:
                if (BooleanFlagOn(volumeProps->DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) {
                    VolumeInfo->VolumeType = ShadowVolumeRemovable;
                } else if (BooleanFlagOn(volumeProps->DeviceCharacteristics, FILE_FLOPPY_DISKETTE)) {
                    VolumeInfo->VolumeType = ShadowVolumeRemovable;
                } else {
                    VolumeInfo->VolumeType = ShadowVolumeFixed;
                }
                break;
        }

        //
        // Copy file system name safely — only when we have a full (non-truncated) response
        //
        if (volumeProps->FileSystemDriverName.Length > 0 &&
            volumeProps->FileSystemDriverName.Buffer != NULL) {
            USHORT copyLength = min(
                volumeProps->FileSystemDriverName.Length,
                (USHORT)(sizeof(VolumeInfo->FileSystemName) - sizeof(WCHAR))
            );
            RtlCopyMemory(
                VolumeInfo->FileSystemName,
                volumeProps->FileSystemDriverName.Buffer,
                copyLength
            );
            VolumeInfo->FileSystemName[copyLength / sizeof(WCHAR)] = L'\0';
        }

        //
        // Set capabilities based on device characteristics
        //
        VolumeInfo->IsReadOnly = BooleanFlagOn(volumeProps->DeviceCharacteristics,
                                                FILE_READ_ONLY_DEVICE);
    } else if (status == STATUS_BUFFER_OVERFLOW) {
        //
        // Buffer was too small for full response.
        // Only use fixed-size fields (DeviceType, DeviceCharacteristics)
        // which are at known offsets. Do NOT access variable-length strings.
        //
        switch (volumeProps->DeviceType) {
            case FILE_DEVICE_NETWORK_FILE_SYSTEM:
            case FILE_DEVICE_DFS:
            case FILE_DEVICE_DFS_FILE_SYSTEM:
                VolumeInfo->VolumeType = ShadowVolumeNetwork;
                VolumeInfo->IsNetworkDrive = TRUE;
                break;

            case FILE_DEVICE_CD_ROM:
            case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
            case FILE_DEVICE_DVD:
                VolumeInfo->VolumeType = ShadowVolumeCDROM;
                break;

            case FILE_DEVICE_VIRTUAL_DISK:
                VolumeInfo->VolumeType = ShadowVolumeVirtual;
                break;

            default:
                if (BooleanFlagOn(volumeProps->DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) {
                    VolumeInfo->VolumeType = ShadowVolumeRemovable;
                } else {
                    VolumeInfo->VolumeType = ShadowVolumeFixed;
                }
                break;
        }

        VolumeInfo->IsReadOnly = BooleanFlagOn(volumeProps->DeviceCharacteristics,
                                                FILE_READ_ONLY_DEVICE);
        status = STATUS_SUCCESS;
    }

    //
    // Populate volume capability flags using FltQueryVolumeInformation
    //
    if (NT_SUCCESS(status)) {
        union {
            FILE_FS_ATTRIBUTE_INFORMATION AttrInfo;
            UCHAR Buffer[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 128 * sizeof(WCHAR)];
        } attrBuffer;
        NTSTATUS attrStatus;

        RtlZeroMemory(&attrBuffer, sizeof(attrBuffer));
        attrStatus = FltQueryVolumeInformation(
            Instance,
            NULL,
            &attrBuffer.AttrInfo,
            sizeof(attrBuffer),
            FileFsAttributeInformation
        );

        if (NT_SUCCESS(attrStatus)) {
            VolumeInfo->FileSystemFlags = attrBuffer.AttrInfo.FileSystemAttributes;
            VolumeInfo->MaxComponentLength = attrBuffer.AttrInfo.MaximumComponentNameLength;

            VolumeInfo->SupportsStreams = BooleanFlagOn(
                attrBuffer.AttrInfo.FileSystemAttributes, FILE_NAMED_STREAMS);
            VolumeInfo->SupportsHardLinks = BooleanFlagOn(
                attrBuffer.AttrInfo.FileSystemAttributes, FILE_SUPPORTS_HARD_LINKS);
            VolumeInfo->SupportsReparsePoints = BooleanFlagOn(
                attrBuffer.AttrInfo.FileSystemAttributes, FILE_SUPPORTS_REPARSE_POINTS);
            VolumeInfo->SupportsSecurity = BooleanFlagOn(
                attrBuffer.AttrInfo.FileSystemAttributes, FILE_PERSISTENT_ACLS);
            VolumeInfo->SupportsCompression = BooleanFlagOn(
                attrBuffer.AttrInfo.FileSystemAttributes, FILE_FILE_COMPRESSION);
            VolumeInfo->SupportsEncryption = BooleanFlagOn(
                attrBuffer.AttrInfo.FileSystemAttributes, FILE_SUPPORTS_ENCRYPTION);
        }
    }

    //
    // Get volume serial number using proper API
    //
    ShadowStrikeGetVolumeSerial(Instance, &VolumeInfo->VolumeSerial);

    FltObjectDereference(volume);
    ExFreePoolWithTag(volumeProps, SHADOW_FILE_TAG);

    return status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetVolumeType(
    PFLT_INSTANCE Instance,
    PSHADOW_VOLUME_TYPE VolumeType
    )
{
    NTSTATUS status;
    SHADOW_VOLUME_INFO volumeInfo;

    PAGED_CODE();

    *VolumeType = ShadowVolumeUnknown;

    status = ShadowStrikeGetVolumeInfo(Instance, &volumeInfo);
    if (NT_SUCCESS(status)) {
        *VolumeType = volumeInfo.VolumeType;
    }

    return status;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsNetworkVolume(
    PFLT_INSTANCE Instance
    )
{
    SHADOW_VOLUME_TYPE volumeType;

    PAGED_CODE();

    if (NT_SUCCESS(ShadowStrikeGetVolumeType(Instance, &volumeType))) {
        return (volumeType == ShadowVolumeNetwork);
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsRemovableVolume(
    PFLT_INSTANCE Instance
    )
{
    SHADOW_VOLUME_TYPE volumeType;

    PAGED_CODE();

    if (NT_SUCCESS(ShadowStrikeGetVolumeType(Instance, &volumeType))) {
        return (volumeType == ShadowVolumeRemovable);
    }

    return FALSE;
}

// ============================================================================
// FILE READING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeReadFileHeader(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BytesRead
    )
{
    PAGED_CODE();

    return ShadowStrikeReadFileAtOffset(
        Instance,
        FileObject,
        0,              // Offset 0 = header
        Buffer,
        BufferSize,
        BytesRead
    );
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeReadFileAtOffset(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    LONGLONG Offset,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BytesRead
    )
{
    NTSTATUS status;
    LARGE_INTEGER byteOffset;

    PAGED_CODE();

    *BytesRead = 0;

    if (Instance == NULL || FileObject == NULL || Buffer == NULL || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate offset is not negative
    //
    if (Offset < 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate BufferSize is within safe limits
    //
    if (BufferSize > SHADOW_MAX_FILE_READ_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    byteOffset.QuadPart = Offset;

    //
    // Use FltReadFile for safe kernel-mode file reading
    //
    status = FltReadFile(
        Instance,
        FileObject,
        &byteOffset,
        BufferSize,
        Buffer,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        BytesRead,
        NULL,           // CallbackRoutine
        NULL            // CallbackContext
    );

    //
    // EOF is not an error for partial reads
    //
    if (status == STATUS_END_OF_FILE && *BytesRead > 0) {
        status = STATUS_SUCCESS;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInitFileReadContext(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    ULONG ChunkSize,
    PSHADOW_FILE_READ_CONTEXT Context
    )
{
    NTSTATUS status;
    LONGLONG fileSize;

    PAGED_CODE();

    RtlZeroMemory(Context, sizeof(SHADOW_FILE_READ_CONTEXT));

    if (Instance == NULL || FileObject == NULL || ChunkSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate chunk size
    //
    if (ChunkSize > SHADOW_MAX_FILE_READ_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get file size
    //
    status = ShadowStrikeGetFileSize(Instance, FileObject, &fileSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Allocate read buffer — prefer lookaside for standard chunk size.
    // Use rundown protection to prevent use-after-free if the lookaside
    // is deleted concurrently during driver unload.
    //
    Context->UsedLookaside = FALSE;
    if (InterlockedCompareExchange(&g_LookasideInitialized, 1, 1) == 1 &&
        ChunkSize == SHADOW_FILE_READ_CHUNK_SIZE) {

        if (ExAcquireRundownProtection(&g_LookasideRundown)) {
            Context->Buffer = ExAllocateFromNPagedLookasideList(&g_FileBufferLookaside);
            if (Context->Buffer != NULL) {
                Context->UsedLookaside = TRUE;
            } else {
                ExReleaseRundownProtection(&g_LookasideRundown);
            }
        }
    }

    if (Context->Buffer == NULL) {
        Context->Buffer = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            ChunkSize,
            SHADOW_FILEBUF_TAG
        );
        Context->UsedLookaside = FALSE;
    }

    if (Context->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Take references on Instance and FileObject to prevent use-after-free.
    // The caller's handles may be closed while the read context is still alive.
    //
    FltObjectReference(Instance);
    ObReferenceObject(FileObject);
    Context->ReferencesHeld = TRUE;

    Context->Instance = Instance;
    Context->FileObject = FileObject;
    Context->FileSize = fileSize;
    Context->CurrentOffset = 0;
    Context->BufferSize = ChunkSize;
    Context->BytesRead = 0;
    Context->EndOfFile = (fileSize == 0);
    Context->LastStatus = STATUS_SUCCESS;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeReadNextChunk(
    PSHADOW_FILE_READ_CONTEXT Context
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (Context == NULL || Context->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Context->EndOfFile) {
        return STATUS_END_OF_FILE;
    }

    //
    // Read next chunk
    //
    status = ShadowStrikeReadFileAtOffset(
        Context->Instance,
        Context->FileObject,
        Context->CurrentOffset,
        Context->Buffer,
        Context->BufferSize,
        &Context->BytesRead
    );

    Context->LastStatus = status;

    if (!NT_SUCCESS(status)) {
        Context->EndOfFile = TRUE;
        return status;
    }

    //
    // Update position
    //
    Context->CurrentOffset += Context->BytesRead;

    //
    // Check for EOF
    //
    if (Context->BytesRead < Context->BufferSize ||
        Context->CurrentOffset >= Context->FileSize) {
        Context->EndOfFile = TRUE;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeCleanupFileReadContext(
    PSHADOW_FILE_READ_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    PAGED_CODE();

    if (Context->Buffer != NULL) {
        if (Context->UsedLookaside) {
            //
            // Return to lookaside list, then release rundown protection.
            // The rundown was acquired in InitFileReadContext.
            //
            ExFreeToNPagedLookasideList(&g_FileBufferLookaside, Context->Buffer);
            ExReleaseRundownProtection(&g_LookasideRundown);
        } else {
            ExFreePoolWithTag(Context->Buffer, SHADOW_FILEBUF_TAG);
        }
        Context->Buffer = NULL;
    }

    //
    // Release references taken during initialization
    //
    if (Context->ReferencesHeld) {
        if (Context->FileObject != NULL) {
            ObDereferenceObject(Context->FileObject);
        }
        if (Context->Instance != NULL) {
            FltObjectDereference(Context->Instance);
        }
    }

    RtlZeroMemory(Context, sizeof(SHADOW_FILE_READ_CONTEXT));
}

// ============================================================================
// REPARSE POINT OPERATIONS
// ============================================================================

/**
 * @brief Validate reparse data buffer structure
 */
static
BOOLEAN
ShadowpValidateReparseBuffer(
    _In_ PREPARSE_DATA_BUFFER ReparseData,
    _In_ ULONG BufferSize
    )
{
    ULONG minSize;
    ULONG dataAreaSize;

    //
    // Minimum size for reparse data header
    //
    minSize = REPARSE_DATA_BUFFER_HEADER_SIZE;
    if (BufferSize < minSize) {
        return FALSE;
    }

    //
    // Validate ReparseDataLength against actual buffer.
    // The total structure is header + ReparseDataLength.
    //
    if ((SIZE_T)REPARSE_DATA_BUFFER_HEADER_SIZE + ReparseData->ReparseDataLength > BufferSize) {
        return FALSE;
    }

    //
    // Validate based on reparse tag
    //
    if (ReparseData->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        minSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer);
        if (BufferSize < minSize) {
            return FALSE;
        }

        //
        // Calculate actual data area available for path strings
        //
        dataAreaSize = ReparseData->ReparseDataLength;

        if ((ULONG)ReparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset +
            ReparseData->SymbolicLinkReparseBuffer.SubstituteNameLength > dataAreaSize) {
            return FALSE;
        }

        if ((ULONG)ReparseData->SymbolicLinkReparseBuffer.PrintNameOffset +
            ReparseData->SymbolicLinkReparseBuffer.PrintNameLength > dataAreaSize) {
            return FALSE;
        }
    } else if (ReparseData->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        minSize = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer);
        if (BufferSize < minSize) {
            return FALSE;
        }

        dataAreaSize = ReparseData->ReparseDataLength;

        if ((ULONG)ReparseData->MountPointReparseBuffer.SubstituteNameOffset +
            ReparseData->MountPointReparseBuffer.SubstituteNameLength > dataAreaSize) {
            return FALSE;
        }

        if ((ULONG)ReparseData->MountPointReparseBuffer.PrintNameOffset +
            ReparseData->MountPointReparseBuffer.PrintNameLength > dataAreaSize) {
            return FALSE;
        }
    }

    return TRUE;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeIsReparsePoint(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PBOOLEAN IsReparse,
    PULONG ReparseTag
    )
{
    NTSTATUS status;
    FILE_ATTRIBUTE_TAG_INFORMATION tagInfo;
    ULONG returnLength;

    PAGED_CODE();

    *IsReparse = FALSE;
    if (ReparseTag != NULL) {
        *ReparseTag = 0;
    }

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        Instance,
        FileObject,
        &tagInfo,
        sizeof(FILE_ATTRIBUTE_TAG_INFORMATION),
        FileAttributeTagInformation,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        *IsReparse = BooleanFlagOn(tagInfo.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT);

        if (*IsReparse && ReparseTag != NULL) {
            *ReparseTag = tagInfo.ReparseTag;
        }
    }

    return status;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsSymbolicLink(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject
    )
{
    BOOLEAN isReparse;
    ULONG reparseTag;

    PAGED_CODE();

    if (NT_SUCCESS(ShadowStrikeIsReparsePoint(Instance, FileObject, &isReparse, &reparseTag))) {
        return (isReparse && reparseTag == IO_REPARSE_TAG_SYMLINK);
    }

    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetReparseTarget(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PUNICODE_STRING TargetPath
    )
{
    NTSTATUS status;
    PUCHAR buffer = NULL;
    PREPARSE_DATA_BUFFER reparseData;
    ULONG returnLength;
    PWCHAR targetBuffer;
    USHORT targetLength;
    SIZE_T allocationSize;
    const ULONG bufferSize = MAXIMUM_REPARSE_DATA_BUFFER_SIZE;

    PAGED_CODE();

    TargetPath->Buffer = NULL;
    TargetPath->Length = 0;
    TargetPath->MaximumLength = 0;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate buffer from pool (too large for stack)
    //
    buffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        bufferSize,
        SHADOW_FILE_TAG
    );

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    reparseData = (PREPARSE_DATA_BUFFER)buffer;

    //
    // Query reparse point data
    //
    status = FltFsControlFile(
        Instance,
        FileObject,
        FSCTL_GET_REPARSE_POINT,
        NULL,
        0,
        buffer,
        bufferSize,
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
        return status;
    }

    //
    // Validate reparse buffer structure
    //
    if (!ShadowpValidateReparseBuffer(reparseData, returnLength)) {
        ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    //
    // Extract target path based on reparse type.
    // Validate both against ReparseDataLength AND against actual returnLength
    // to prevent out-of-bounds reads from crafted reparse points.
    //
    if (reparseData->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        USHORT offset = reparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset;
        ULONG pathBufferBase;
        targetLength = reparseData->SymbolicLinkReparseBuffer.SubstituteNameLength;

        if (offset + targetLength > reparseData->ReparseDataLength) {
            ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
            return STATUS_INVALID_BUFFER_SIZE;
        }

        //
        // Validate that the data actually fits within the returned buffer
        //
        pathBufferBase = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer);
        if ((SIZE_T)pathBufferBase + offset + targetLength > returnLength) {
            ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
            return STATUS_INVALID_BUFFER_SIZE;
        }

        targetBuffer = (PWCHAR)((PUCHAR)reparseData->SymbolicLinkReparseBuffer.PathBuffer + offset);

    } else if (reparseData->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        USHORT offset = reparseData->MountPointReparseBuffer.SubstituteNameOffset;
        ULONG pathBufferBase;
        targetLength = reparseData->MountPointReparseBuffer.SubstituteNameLength;

        if (offset + targetLength > reparseData->ReparseDataLength) {
            ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
            return STATUS_INVALID_BUFFER_SIZE;
        }

        pathBufferBase = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer);
        if ((SIZE_T)pathBufferBase + offset + targetLength > returnLength) {
            ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
            return STATUS_INVALID_BUFFER_SIZE;
        }

        targetBuffer = (PWCHAR)((PUCHAR)reparseData->MountPointReparseBuffer.PathBuffer + offset);

    } else {
        ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Calculate allocation size with overflow check
    //
    allocationSize = (SIZE_T)targetLength + sizeof(WCHAR);
    if (allocationSize < targetLength || allocationSize > SHADOW_MAX_PATH_BYTES) {
        ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate and copy target path
    //
    TargetPath->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
        allocationSize,
        SHADOW_FILEPATH_TAG
    );

    if (TargetPath->Buffer == NULL) {
        ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(TargetPath->Buffer, targetBuffer, targetLength);
    TargetPath->Buffer[targetLength / sizeof(WCHAR)] = L'\0';
    TargetPath->Length = targetLength;
    TargetPath->MaximumLength = (USHORT)min(allocationSize, MAXUSHORT);

    ExFreePoolWithTag(buffer, SHADOW_FILE_TAG);

    return STATUS_SUCCESS;
}

// ============================================================================
// SECURITY OPERATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetFileOwner(
    PFLT_INSTANCE Instance,
    PFILE_OBJECT FileObject,
    PSID* OwnerSid,
    PULONG SidLength
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    ULONG lengthNeeded = 0;
    ULONG secBufferSize = 512;
    PSID owner;
    BOOLEAN ownerDefaulted;
    ULONG sidLength;
    PSID sidCopy;

    PAGED_CODE();

    *OwnerSid = NULL;
    *SidLength = 0;

    if (Instance == NULL || FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate initial security descriptor buffer
    //
    securityDescriptor = (PSECURITY_DESCRIPTOR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        secBufferSize,
        SHADOW_FILE_TAG
    );

    if (securityDescriptor == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Query security descriptor — retry with proper size if initial buffer is too small
    //
    status = FltQuerySecurityObject(
        Instance,
        FileObject,
        OWNER_SECURITY_INFORMATION,
        securityDescriptor,
        secBufferSize,
        &lengthNeeded
    );

    if (status == STATUS_BUFFER_TOO_SMALL && lengthNeeded > secBufferSize) {
        ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);

        //
        // Cap retry size to prevent excessive allocation from malicious input
        //
        if (lengthNeeded > 64 * 1024) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        secBufferSize = lengthNeeded;
        securityDescriptor = (PSECURITY_DESCRIPTOR)ExAllocatePool2(
            POOL_FLAG_PAGED,
            secBufferSize,
            SHADOW_FILE_TAG
        );

        if (securityDescriptor == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = FltQuerySecurityObject(
            Instance,
            FileObject,
            OWNER_SECURITY_INFORMATION,
            securityDescriptor,
            secBufferSize,
            &lengthNeeded
        );
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);
        return status;
    }

    //
    // Get owner SID from security descriptor
    //
    status = RtlGetOwnerSecurityDescriptor(
        securityDescriptor,
        &owner,
        &ownerDefaulted
    );

    if (!NT_SUCCESS(status) || owner == NULL) {
        ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);
        return STATUS_NOT_FOUND;
    }

    //
    // Validate SID before using
    //
    if (!RtlValidSid(owner)) {
        ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);
        return STATUS_INVALID_SID;
    }

    //
    // Calculate SID length and allocate copy
    //
    sidLength = RtlLengthSid(owner);

    if (sidLength == 0 || sidLength > SECURITY_MAX_SID_SIZE) {
        ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);
        return STATUS_INVALID_SID;
    }

    sidCopy = (PSID)ExAllocatePool2(
        POOL_FLAG_PAGED,
        sidLength,
        SHADOW_FILE_TAG
    );

    if (sidCopy == NULL) {
        ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlCopySid(sidLength, sidCopy, owner);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(sidCopy, SHADOW_FILE_TAG);
        ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);
        return status;
    }

    *OwnerSid = sidCopy;
    *SidLength = sidLength;

    ExFreePoolWithTag(securityDescriptor, SHADOW_FILE_TAG);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeFreeFileSid(
    PSID Sid
    )
{
    if (Sid != NULL) {
        ExFreePoolWithTag(Sid, SHADOW_FILE_TAG);
    }
}

// ============================================================================
// CALLBACK DATA HELPERS
// ============================================================================

_Use_decl_annotations_
SHADOW_FILE_DISPOSITION
ShadowStrikeGetFileDisposition(
    PFLT_CALLBACK_DATA Data
    )
{
    ULONG createDisposition;

    if (Data == NULL) {
        return ShadowDispositionOpen;
    }

    //
    // Validate Iopb is present
    //
    if (Data->Iopb == NULL) {
        return ShadowDispositionOpen;
    }

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return ShadowDispositionOpen;
    }

    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    switch (createDisposition) {
        case FILE_SUPERSEDE:
            return ShadowDispositionSupersede;
        case FILE_CREATE:
            return ShadowDispositionCreate;
        case FILE_OPEN:
            return ShadowDispositionOpen;
        case FILE_OPEN_IF:
            return ShadowDispositionOpenIf;
        case FILE_OVERWRITE:
            return ShadowDispositionOverwrite;
        case FILE_OVERWRITE_IF:
            return ShadowDispositionOverwriteIf;
        default:
            return ShadowDispositionOpen;
    }
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsWriteAccess(
    PFLT_CALLBACK_DATA Data
    )
{
    ACCESS_MASK desiredAccess;
    ULONG createDisposition;

    if (Data == NULL) {
        return FALSE;
    }

    //
    // Validate Iopb is present
    //
    if (Data->Iopb == NULL) {
        return FALSE;
    }

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return FALSE;
    }

    //
    // Validate SecurityContext is present
    //
    if (Data->Iopb->Parameters.Create.SecurityContext == NULL) {
        return FALSE;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    //
    // Check for write-related access rights
    //
    if (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                         FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                         GENERIC_WRITE | DELETE)) {
        return TRUE;
    }

    //
    // Check disposition
    //
    if (createDisposition == FILE_SUPERSEDE ||
        createDisposition == FILE_CREATE ||
        createDisposition == FILE_OVERWRITE ||
        createDisposition == FILE_OVERWRITE_IF) {
        return TRUE;
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsExecuteAccess(
    PFLT_CALLBACK_DATA Data
    )
{
    ACCESS_MASK desiredAccess;

    if (Data == NULL) {
        return FALSE;
    }

    //
    // Validate Iopb is present
    //
    if (Data->Iopb == NULL) {
        return FALSE;
    }

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        //
        // Check for section acquisition — only treat as execute if
        // the page protection indicates execution intent.
        //
        if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION) {
            ULONG pageProtection =
                Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;

            if (pageProtection == PAGE_EXECUTE ||
                pageProtection == PAGE_EXECUTE_READ ||
                pageProtection == PAGE_EXECUTE_READWRITE ||
                pageProtection == PAGE_EXECUTE_WRITECOPY) {
                return TRUE;
            }
        }
        return FALSE;
    }

    //
    // Validate SecurityContext is present
    //
    if (Data->Iopb->Parameters.Create.SecurityContext == NULL) {
        return FALSE;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    //
    // Check for execute access
    //
    if (desiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) {
        return TRUE;
    }

    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeIsDirectory(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PBOOLEAN IsDirectory
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION standardInfo;
    ULONG returnLength;

    PAGED_CODE();

    *IsDirectory = FALSE;

    if (Data == NULL || FltObjects == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate FltObjects members
    //
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate Iopb if checking CREATE options
    //
    if (Data->Iopb != NULL && Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        if (BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
            *IsDirectory = TRUE;
            return STATUS_SUCCESS;
        }
    }

    //
    // Query file information
    //
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &standardInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        *IsDirectory = standardInfo.Directory;
    }

    return status;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsKernelModeOperation(
    PFLT_CALLBACK_DATA Data
    )
{
    if (Data == NULL) {
        return FALSE;
    }

    return (Data->RequestorMode == KernelMode);
}
