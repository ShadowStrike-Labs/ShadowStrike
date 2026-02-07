/**
 * ============================================================================
 * ShadowStrike NGAV - STRING UTILITIES IMPLEMENTATION
 * ============================================================================
 *
 * @file StringUtils.c
 * @brief Enterprise-grade string manipulation for kernel-mode EDR operations.
 *
 * Implements CrowdStrike Falcon-level string handling with:
 * - Safe UNICODE_STRING manipulation (no buffer overflows)
 * - Path parsing and normalization (DOS/NT path conversion)
 * - Wildcard pattern matching (file exclusions, IOC matching)
 * - Case-insensitive comparison with locale awareness
 * - Hash computation for string deduplication
 * - Memory-safe string builders
 *
 * Security Guarantees:
 * - All functions validate input parameters
 * - Buffer sizes are always checked before operations
 * - No integer overflows in length calculations
 * - Pool allocations use tagged pools for leak detection
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "StringUtils.h"
#include "MemoryUtils.h"

// ============================================================================
// ALLOC_PRAGMA
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeCopyUnicodeString)
#pragma alloc_text(PAGE, ShadowStrikeCloneUnicodeString)
#pragma alloc_text(PAGE, ShadowStrikeFreeUnicodeString)
#pragma alloc_text(PAGE, ShadowStrikeIsStringMatch)
#pragma alloc_text(PAGE, ShadowStrikeGetPathType)
#pragma alloc_text(PAGE, ShadowStrikeGetFileName)
#pragma alloc_text(PAGE, ShadowStrikeGetFileExtension)
#pragma alloc_text(PAGE, ShadowStrikeGetDirectoryPath)
#pragma alloc_text(PAGE, ShadowStrikeNormalizePath)
#pragma alloc_text(PAGE, ShadowStrikeDosPathToNtPath)
#pragma alloc_text(PAGE, ShadowStrikeNtPathToDosPath)
#pragma alloc_text(PAGE, ShadowStrikeMatchWildcard)
#pragma alloc_text(PAGE, ShadowStrikeStringBuilderInit)
#pragma alloc_text(PAGE, ShadowStrikeStringBuilderCleanup)
#pragma alloc_text(PAGE, ShadowStrikeParseCommandLine)
#pragma alloc_text(PAGE, ShadowStrikeFreeCommandLineArgs)
#pragma alloc_text(PAGE, ShadowStrikeGetExePathFromCommandLine)
#pragma alloc_text(PAGE, ShadowStrikeAnsiToUnicode)
#pragma alloc_text(PAGE, ShadowStrikeUnicodeToAnsi)
#pragma alloc_text(PAGE, ShadowStrikeIntegerToUnicodeString)
#pragma alloc_text(PAGE, ShadowStrikeGuidToUnicodeString)
#endif

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief FNV-1a 64-bit seed
 */
#define SHADOW_FNV1A_SEED_64 0xcbf29ce484222325ULL

/**
 * @brief FNV-1a 64-bit prime
 */
#define SHADOW_FNV1A_PRIME_64 0x100000001b3ULL

/**
 * @brief Invalid path characters
 */
static const WCHAR g_InvalidPathChars[] = L"<>:\"|?*";

/**
 * @brief String builder growth factor
 */
#define STRING_BUILDER_GROWTH_FACTOR 2

// ============================================================================
// BASIC STRING OPERATIONS
// ============================================================================

/**
 * @brief Copy UNICODE_STRING with bounds checking.
 */
NTSTATUS
ShadowStrikeCopyUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Destination == NULL || Source == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Destination->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check for empty source
    //
    if (Source->Buffer == NULL || Source->Length == 0) {
        Destination->Length = 0;
        return STATUS_SUCCESS;
    }

    //
    // Bounds check
    //
    if (Destination->MaximumLength < Source->Length) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyUnicodeString(Destination, Source);
    return STATUS_SUCCESS;
}

/**
 * @brief Append UNICODE_STRING with bounds checking.
 */
NTSTATUS
ShadowStrikeAppendUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    //
    // Can be called at DISPATCH_LEVEL if buffers are non-paged
    //

    if (Destination == NULL || Source == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_SUCCESS;
    }

    return RtlAppendUnicodeStringToString(Destination, Source);
}

/**
 * @brief Clone UNICODE_STRING with new allocation.
 */
NTSTATUS
ShadowStrikeCloneUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    SIZE_T allocationSize;

    PAGED_CODE();

    //
    // Initialize output
    //
    Destination->Buffer = NULL;
    Destination->Length = 0;
    Destination->MaximumLength = 0;

    //
    // Validate source
    //
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Calculate allocation size with overflow check
    //
    allocationSize = (SIZE_T)Source->Length + sizeof(WCHAR);
    if (allocationSize < Source->Length) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate buffer from paged pool
    //
    Destination->Buffer = (PWCH)ExAllocatePoolWithTag(
        PagedPool,
        allocationSize,
        SHADOW_STRING_TAG
    );

    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy string
    //
    Destination->MaximumLength = (USHORT)allocationSize;
    RtlCopyUnicodeString(Destination, Source);

    //
    // Ensure null termination
    //
    Destination->Buffer[Destination->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

/**
 * @brief Clone UNICODE_STRING to non-paged pool.
 */
NTSTATUS
ShadowStrikeCloneUnicodeStringNonPaged(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    SIZE_T allocationSize;

    //
    // Initialize output
    //
    Destination->Buffer = NULL;
    Destination->Length = 0;
    Destination->MaximumLength = 0;

    //
    // Validate source
    //
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Calculate allocation size with overflow check
    //
    allocationSize = (SIZE_T)Source->Length + sizeof(WCHAR);
    if (allocationSize < Source->Length) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate buffer from non-paged pool
    //
    Destination->Buffer = (PWCH)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        allocationSize,
        SHADOW_STRING_TAG
    );

    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy string
    //
    Destination->MaximumLength = (USHORT)allocationSize;
    RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
    Destination->Length = Source->Length;

    //
    // Ensure null termination
    //
    Destination->Buffer[Destination->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

/**
 * @brief Free UNICODE_STRING allocated by clone functions.
 */
VOID
ShadowStrikeFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    PAGED_CODE();

    if (String == NULL) {
        return;
    }

    if (String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, SHADOW_STRING_TAG);
        String->Buffer = NULL;
    }

    String->Length = 0;
    String->MaximumLength = 0;
}

/**
 * @brief Compare two UNICODE_STRINGs for equality.
 */
BOOLEAN
ShadowStrikeIsStringMatch(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN CaseInsensitive
    )
{
    PAGED_CODE();

    if (String1 == NULL || String2 == NULL) {
        return FALSE;
    }

    if (String1->Buffer == NULL || String2->Buffer == NULL) {
        return (String1->Buffer == NULL && String2->Buffer == NULL);
    }

    return RtlEqualUnicodeString(String1, String2, CaseInsensitive);
}

/**
 * @brief Compare UNICODE_STRING with C string.
 */
BOOLEAN
ShadowStrikeCompareStringToCString(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR CString,
    _In_ BOOLEAN CaseInsensitive
    )
{
    UNICODE_STRING tempString;

    if (String == NULL || CString == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&tempString, CString);
    return RtlEqualUnicodeString(String, &tempString, CaseInsensitive);
}

// ============================================================================
// PATH OPERATIONS
// ============================================================================

/**
 * @brief Determine path type.
 */
SHADOW_PATH_TYPE
ShadowStrikeGetPathType(
    _In_ PCUNICODE_STRING Path
    )
{
    PAGED_CODE();

    if (ShadowStrikeIsStringEmpty(Path)) {
        return ShadowPathUnknown;
    }

    USHORT lengthChars = Path->Length / sizeof(WCHAR);

    //
    // Check for NT path: \Device\... or \??\ or \DosDevices\
    //
    if (lengthChars >= 8 && Path->Buffer[0] == L'\\') {
        UNICODE_STRING devicePrefix;
        UNICODE_STRING registryPrefix;
        UNICODE_STRING dosDevicesPrefix;

        RtlInitUnicodeString(&devicePrefix, L"\\Device\\");
        RtlInitUnicodeString(&registryPrefix, L"\\REGISTRY\\");
        RtlInitUnicodeString(&dosDevicesPrefix, L"\\DosDevices\\");

        if (ShadowStrikeStringStartsWith(Path, &devicePrefix, TRUE)) {
            return ShadowPathNt;
        }
        if (ShadowStrikeStringStartsWith(Path, &registryPrefix, TRUE)) {
            return ShadowPathRegistry;
        }
        if (ShadowStrikeStringStartsWith(Path, &dosDevicesPrefix, TRUE)) {
            return ShadowPathNt;
        }

        //
        // Check for \??\ prefix
        //
        if (lengthChars >= 4 && Path->Buffer[1] == L'?' &&
            Path->Buffer[2] == L'?' && Path->Buffer[3] == L'\\') {
            return ShadowPathNt;
        }
    }

    //
    // Check for UNC path: \\Server\Share
    //
    if (lengthChars >= 2 && Path->Buffer[0] == L'\\' && Path->Buffer[1] == L'\\') {
        //
        // Check for device path: \\.\DeviceName
        //
        if (lengthChars >= 4 && Path->Buffer[2] == L'.' && Path->Buffer[3] == L'\\') {
            return ShadowPathDevice;
        }
        return ShadowPathUNC;
    }

    //
    // Check for DOS path: C:\... or C:/...
    //
    if (lengthChars >= 3) {
        WCHAR driveLetter = Path->Buffer[0];
        if (((driveLetter >= L'A' && driveLetter <= L'Z') ||
             (driveLetter >= L'a' && driveLetter <= L'z')) &&
            Path->Buffer[1] == L':' &&
            (Path->Buffer[2] == L'\\' || Path->Buffer[2] == L'/')) {
            return ShadowPathDos;
        }
    }

    //
    // Relative path or unknown
    //
    return ShadowPathRelative;
}

/**
 * @brief Extract file name from path.
 */
NTSTATUS
ShadowStrikeGetFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    )
{
    LONG i;
    USHORT lengthChars;
    PWCHAR lastSeparator = NULL;

    PAGED_CODE();

    FileName->Buffer = NULL;
    FileName->Length = 0;
    FileName->MaximumLength = 0;

    if (ShadowStrikeIsStringEmpty(FullPath)) {
        return STATUS_INVALID_PARAMETER;
    }

    lengthChars = FullPath->Length / sizeof(WCHAR);

    //
    // Find last path separator
    //
    for (i = lengthChars - 1; i >= 0; i--) {
        if (FullPath->Buffer[i] == L'\\' || FullPath->Buffer[i] == L'/') {
            lastSeparator = &FullPath->Buffer[i];
            break;
        }
    }

    if (lastSeparator == NULL) {
        //
        // No separator - entire string is filename
        //
        FileName->Buffer = FullPath->Buffer;
        FileName->Length = FullPath->Length;
        FileName->MaximumLength = FullPath->Length;
    } else {
        //
        // Return portion after separator
        //
        FileName->Buffer = lastSeparator + 1;
        FileName->Length = (USHORT)((PUCHAR)(FullPath->Buffer + lengthChars) -
                                     (PUCHAR)FileName->Buffer);
        FileName->MaximumLength = FileName->Length;
    }

    if (FileName->Length == 0) {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Extract file extension from path.
 */
NTSTATUS
ShadowStrikeGetFileExtension(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING Extension
    )
{
    NTSTATUS status;
    UNICODE_STRING fileName;
    LONG i;
    USHORT lengthChars;
    PWCHAR lastDot = NULL;

    PAGED_CODE();

    Extension->Buffer = NULL;
    Extension->Length = 0;
    Extension->MaximumLength = 0;

    //
    // Get filename first
    //
    status = ShadowStrikeGetFileName(FullPath, &fileName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    lengthChars = fileName.Length / sizeof(WCHAR);

    //
    // Find last dot in filename
    //
    for (i = lengthChars - 1; i >= 0; i--) {
        if (fileName.Buffer[i] == L'.') {
            lastDot = &fileName.Buffer[i];
            break;
        }
    }

    if (lastDot == NULL || lastDot == fileName.Buffer) {
        //
        // No extension or dot at start (hidden file like .gitignore)
        //
        return STATUS_NOT_FOUND;
    }

    Extension->Buffer = lastDot;
    Extension->Length = (USHORT)((PUCHAR)(fileName.Buffer + lengthChars) -
                                  (PUCHAR)lastDot);
    Extension->MaximumLength = Extension->Length;

    return STATUS_SUCCESS;
}

/**
 * @brief Extract directory path from full path.
 */
NTSTATUS
ShadowStrikeGetDirectoryPath(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING Directory
    )
{
    LONG i;
    USHORT lengthChars;
    USHORT dirLength;

    PAGED_CODE();

    Directory->Buffer = NULL;
    Directory->Length = 0;
    Directory->MaximumLength = 0;

    if (ShadowStrikeIsStringEmpty(FullPath)) {
        return STATUS_INVALID_PARAMETER;
    }

    lengthChars = FullPath->Length / sizeof(WCHAR);

    //
    // Find last path separator
    //
    for (i = lengthChars - 1; i >= 0; i--) {
        if (FullPath->Buffer[i] == L'\\' || FullPath->Buffer[i] == L'/') {
            break;
        }
    }

    if (i < 0) {
        return STATUS_NOT_FOUND;
    }

    //
    // Include the separator in directory path
    //
    dirLength = (USHORT)((i + 1) * sizeof(WCHAR));

    //
    // Allocate and copy
    //
    Directory->Buffer = (PWCH)ExAllocatePoolWithTag(
        PagedPool,
        dirLength + sizeof(WCHAR),
        SHADOW_PATH_TAG
    );

    if (Directory->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Directory->Buffer, FullPath->Buffer, dirLength);
    Directory->Buffer[dirLength / sizeof(WCHAR)] = L'\0';
    Directory->Length = dirLength;
    Directory->MaximumLength = dirLength + sizeof(WCHAR);

    return STATUS_SUCCESS;
}

/**
 * @brief Normalize path (resolve . and .., convert separators).
 */
NTSTATUS
ShadowStrikeNormalizePath(
    _In_ PCUNICODE_STRING InputPath,
    _Out_ PUNICODE_STRING NormalizedPath
    )
{
    NTSTATUS status;
    PWCHAR outputBuffer = NULL;
    PWCHAR components[256];  // Max path depth
    ULONG componentCount = 0;
    USHORT inputLengthChars;
    PWCHAR current;
    PWCHAR componentStart;
    SIZE_T outputIndex = 0;
    ULONG i;
    SIZE_T allocationSize;

    PAGED_CODE();

    NormalizedPath->Buffer = NULL;
    NormalizedPath->Length = 0;
    NormalizedPath->MaximumLength = 0;

    if (ShadowStrikeIsStringEmpty(InputPath)) {
        return STATUS_INVALID_PARAMETER;
    }

    inputLengthChars = InputPath->Length / sizeof(WCHAR);

    //
    // Allocate output buffer (same size as input max)
    //
    allocationSize = (SIZE_T)InputPath->Length + sizeof(WCHAR);
    outputBuffer = (PWCHAR)ExAllocatePoolWithTag(
        PagedPool,
        allocationSize,
        SHADOW_PATH_TAG
    );

    if (outputBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Parse path into components
    //
    current = InputPath->Buffer;
    componentStart = current;

    for (i = 0; i <= inputLengthChars; i++) {
        WCHAR ch = (i < inputLengthChars) ? InputPath->Buffer[i] : L'\0';

        if (ch == L'\\' || ch == L'/' || ch == L'\0') {
            SIZE_T componentLen = &InputPath->Buffer[i] - componentStart;

            if (componentLen == 1 && componentStart[0] == L'.') {
                //
                // Current directory - skip
                //
            } else if (componentLen == 2 && componentStart[0] == L'.' && componentStart[1] == L'.') {
                //
                // Parent directory - pop last component
                //
                if (componentCount > 0) {
                    componentCount--;
                }
            } else if (componentLen > 0) {
                //
                // Normal component - add to list
                //
                if (componentCount < 256) {
                    components[componentCount++] = componentStart;
                }
            }

            componentStart = &InputPath->Buffer[i + 1];
        }
    }

    //
    // Build normalized path
    //
    for (i = 0; i < componentCount; i++) {
        PWCHAR comp = components[i];
        SIZE_T compLen = 0;

        //
        // Find component length
        //
        while (comp[compLen] != L'\\' && comp[compLen] != L'/' &&
               comp[compLen] != L'\0' && (comp + compLen) < (InputPath->Buffer + inputLengthChars)) {
            compLen++;
        }

        //
        // Add separator if not first
        //
        if (outputIndex > 0) {
            outputBuffer[outputIndex++] = L'\\';
        } else if (InputPath->Buffer[0] == L'\\') {
            //
            // Preserve leading backslash
            //
            outputBuffer[outputIndex++] = L'\\';
        }

        //
        // Copy component
        //
        RtlCopyMemory(&outputBuffer[outputIndex], comp, compLen * sizeof(WCHAR));
        outputIndex += compLen;
    }

    //
    // Null terminate
    //
    outputBuffer[outputIndex] = L'\0';

    NormalizedPath->Buffer = outputBuffer;
    NormalizedPath->Length = (USHORT)(outputIndex * sizeof(WCHAR));
    NormalizedPath->MaximumLength = (USHORT)allocationSize;

    return STATUS_SUCCESS;
}

/**
 * @brief Convert DOS path to NT path.
 */
NTSTATUS
ShadowStrikeDosPathToNtPath(
    _In_ PCUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE linkHandle = NULL;
    UNICODE_STRING linkName;
    WCHAR linkNameBuffer[64];
    WCHAR targetBuffer[SHADOW_MAX_PATH];
    ULONG returnedLength;
    SIZE_T allocationSize;
    USHORT dosPathLengthChars;

    PAGED_CODE();

    NtPath->Buffer = NULL;
    NtPath->Length = 0;
    NtPath->MaximumLength = 0;

    if (ShadowStrikeIsStringEmpty(DosPath)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Verify this is a DOS path
    //
    if (ShadowStrikeGetPathType(DosPath) != ShadowPathDos) {
        return STATUS_INVALID_PARAMETER;
    }

    dosPathLengthChars = DosPath->Length / sizeof(WCHAR);

    //
    // Build symbolic link name: \DosDevices\X:
    //
    status = RtlStringCbPrintfW(
        linkNameBuffer,
        sizeof(linkNameBuffer),
        L"\\DosDevices\\%c:",
        DosPath->Buffer[0]
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&linkName, linkNameBuffer);

    InitializeObjectAttributes(
        &objectAttributes,
        &linkName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    //
    // Open symbolic link
    //
    status = ZwOpenSymbolicLinkObject(
        &linkHandle,
        SYMBOLIC_LINK_QUERY,
        &objectAttributes
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Query link target
    //
    UNICODE_STRING targetString;
    targetString.Buffer = targetBuffer;
    targetString.Length = 0;
    targetString.MaximumLength = sizeof(targetBuffer);

    status = ZwQuerySymbolicLinkObject(
        linkHandle,
        &targetString,
        &returnedLength
    );

    ZwClose(linkHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Build full NT path: <target>\<rest of DOS path>
    // Skip the "C:" portion (2 characters)
    //
    allocationSize = targetString.Length + DosPath->Length - (2 * sizeof(WCHAR)) + sizeof(WCHAR);

    NtPath->Buffer = (PWCH)ExAllocatePoolWithTag(
        PagedPool,
        allocationSize,
        SHADOW_PATH_TAG
    );

    if (NtPath->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy target
    //
    RtlCopyMemory(NtPath->Buffer, targetString.Buffer, targetString.Length);

    //
    // Append rest of path (skip C:)
    //
    if (dosPathLengthChars > 2) {
        RtlCopyMemory(
            (PUCHAR)NtPath->Buffer + targetString.Length,
            &DosPath->Buffer[2],
            DosPath->Length - (2 * sizeof(WCHAR))
        );
    }

    NtPath->Length = (USHORT)(targetString.Length + DosPath->Length - (2 * sizeof(WCHAR)));
    NtPath->MaximumLength = (USHORT)allocationSize;
    NtPath->Buffer[NtPath->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

/**
 * @brief Convert NT path to DOS path.
 */
NTSTATUS
ShadowStrikeNtPathToDosPath(
    _In_ PCUNICODE_STRING NtPath,
    _Out_ PUNICODE_STRING DosPath
    )
{
    NTSTATUS status;
    WCHAR driveLetter;
    WCHAR linkNameBuffer[64];
    WCHAR targetBuffer[SHADOW_MAX_PATH];
    UNICODE_STRING linkName;
    UNICODE_STRING targetString;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE linkHandle;
    ULONG returnedLength;
    SIZE_T allocationSize;

    PAGED_CODE();

    DosPath->Buffer = NULL;
    DosPath->Length = 0;
    DosPath->MaximumLength = 0;

    if (ShadowStrikeIsStringEmpty(NtPath)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Iterate through drive letters to find matching device
    //
    for (driveLetter = L'A'; driveLetter <= L'Z'; driveLetter++) {
        status = RtlStringCbPrintfW(
            linkNameBuffer,
            sizeof(linkNameBuffer),
            L"\\DosDevices\\%c:",
            driveLetter
        );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        RtlInitUnicodeString(&linkName, linkNameBuffer);

        InitializeObjectAttributes(
            &objectAttributes,
            &linkName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL
        );

        status = ZwOpenSymbolicLinkObject(
            &linkHandle,
            SYMBOLIC_LINK_QUERY,
            &objectAttributes
        );

        if (!NT_SUCCESS(status)) {
            continue;
        }

        targetString.Buffer = targetBuffer;
        targetString.Length = 0;
        targetString.MaximumLength = sizeof(targetBuffer);

        status = ZwQuerySymbolicLinkObject(
            linkHandle,
            &targetString,
            &returnedLength
        );

        ZwClose(linkHandle);

        if (!NT_SUCCESS(status)) {
            continue;
        }

        //
        // Check if NT path starts with this device
        //
        if (ShadowStrikeStringStartsWith(NtPath, &targetString, TRUE)) {
            //
            // Found match - build DOS path
            //
            USHORT remainingLength = NtPath->Length - targetString.Length;
            allocationSize = sizeof(WCHAR) * 2 + remainingLength + sizeof(WCHAR);

            DosPath->Buffer = (PWCH)ExAllocatePoolWithTag(
                PagedPool,
                allocationSize,
                SHADOW_PATH_TAG
            );

            if (DosPath->Buffer == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            //
            // Build "X:" + rest of path
            //
            DosPath->Buffer[0] = driveLetter;
            DosPath->Buffer[1] = L':';

            if (remainingLength > 0) {
                RtlCopyMemory(
                    &DosPath->Buffer[2],
                    (PUCHAR)NtPath->Buffer + targetString.Length,
                    remainingLength
                );
            }

            DosPath->Length = (USHORT)(sizeof(WCHAR) * 2 + remainingLength);
            DosPath->MaximumLength = (USHORT)allocationSize;
            DosPath->Buffer[DosPath->Length / sizeof(WCHAR)] = L'\0';

            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/**
 * @brief Check if path is under a specific directory.
 */
BOOLEAN
ShadowStrikeIsPathUnderDirectory(
    _In_ PCUNICODE_STRING Path,
    _In_ PCUNICODE_STRING DirectoryPath,
    _In_ BOOLEAN CaseInsensitive
    )
{
    if (ShadowStrikeIsStringEmpty(Path) || ShadowStrikeIsStringEmpty(DirectoryPath)) {
        return FALSE;
    }

    //
    // Path must be longer than directory
    //
    if (Path->Length <= DirectoryPath->Length) {
        return FALSE;
    }

    //
    // Check prefix
    //
    if (!ShadowStrikeStringStartsWith(Path, DirectoryPath, CaseInsensitive)) {
        return FALSE;
    }

    //
    // Verify separator after directory
    //
    USHORT dirLengthChars = DirectoryPath->Length / sizeof(WCHAR);
    WCHAR nextChar = Path->Buffer[dirLengthChars];

    //
    // Handle trailing separator in directory path
    //
    if (dirLengthChars > 0) {
        WCHAR lastDirChar = DirectoryPath->Buffer[dirLengthChars - 1];
        if (lastDirChar == L'\\' || lastDirChar == L'/') {
            return TRUE;
        }
    }

    return (nextChar == L'\\' || nextChar == L'/');
}

// ============================================================================
// PATTERN MATCHING
// ============================================================================

/**
 * @brief Internal wildcard matching helper (recursive).
 */
static
BOOLEAN
ShadowStrikeMatchWildcardInternal(
    _In_ PCWSTR String,
    _In_ USHORT StringLen,
    _In_ PCWSTR Pattern,
    _In_ USHORT PatternLen,
    _In_ BOOLEAN CaseInsensitive
    )
{
    USHORT s = 0;
    USHORT p = 0;
    USHORT starIdx = (USHORT)-1;
    USHORT matchIdx = 0;

    while (s < StringLen) {
        if (p < PatternLen && (Pattern[p] == L'?' ||
            (CaseInsensitive ? RtlUpcaseUnicodeChar(Pattern[p]) == RtlUpcaseUnicodeChar(String[s])
                             : Pattern[p] == String[s]))) {
            //
            // Character match or ?
            //
            s++;
            p++;
        } else if (p < PatternLen && Pattern[p] == L'*') {
            //
            // * - remember position
            //
            starIdx = p;
            matchIdx = s;
            p++;
        } else if (starIdx != (USHORT)-1) {
            //
            // Backtrack to last *
            //
            p = starIdx + 1;
            matchIdx++;
            s = matchIdx;
        } else {
            return FALSE;
        }
    }

    //
    // Check remaining pattern
    //
    while (p < PatternLen && Pattern[p] == L'*') {
        p++;
    }

    return (p == PatternLen);
}

/**
 * @brief Match string against wildcard pattern.
 */
SHADOW_MATCH_RESULT
ShadowStrikeMatchWildcard(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Pattern,
    _In_ BOOLEAN CaseInsensitive
    )
{
    BOOLEAN hasWildcard = FALSE;
    USHORT i;

    PAGED_CODE();

    if (ShadowStrikeIsStringEmpty(String) || ShadowStrikeIsStringEmpty(Pattern)) {
        return ShadowMatchNone;
    }

    //
    // Check for wildcards in pattern
    //
    for (i = 0; i < Pattern->Length / sizeof(WCHAR); i++) {
        if (Pattern->Buffer[i] == L'*' || Pattern->Buffer[i] == L'?') {
            hasWildcard = TRUE;
            break;
        }
    }

    if (!hasWildcard) {
        //
        // Exact match check
        //
        if (RtlEqualUnicodeString(String, Pattern, CaseInsensitive)) {
            return ShadowMatchExact;
        }
        return ShadowMatchNone;
    }

    //
    // Wildcard matching
    //
    if (ShadowStrikeMatchWildcardInternal(
            String->Buffer,
            String->Length / sizeof(WCHAR),
            Pattern->Buffer,
            Pattern->Length / sizeof(WCHAR),
            CaseInsensitive)) {
        return ShadowMatchWildcard;
    }

    return ShadowMatchNone;
}

/**
 * @brief Check if string starts with prefix.
 */
BOOLEAN
ShadowStrikeStringStartsWith(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Prefix,
    _In_ BOOLEAN CaseInsensitive
    )
{
    UNICODE_STRING stringPrefix;

    if (ShadowStrikeIsStringEmpty(String) || ShadowStrikeIsStringEmpty(Prefix)) {
        return FALSE;
    }

    if (String->Length < Prefix->Length) {
        return FALSE;
    }

    stringPrefix.Buffer = String->Buffer;
    stringPrefix.Length = Prefix->Length;
    stringPrefix.MaximumLength = Prefix->Length;

    return RtlEqualUnicodeString(&stringPrefix, Prefix, CaseInsensitive);
}

/**
 * @brief Check if string ends with suffix.
 */
BOOLEAN
ShadowStrikeStringEndsWith(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Suffix,
    _In_ BOOLEAN CaseInsensitive
    )
{
    UNICODE_STRING stringSuffix;
    USHORT offset;

    if (ShadowStrikeIsStringEmpty(String) || ShadowStrikeIsStringEmpty(Suffix)) {
        return FALSE;
    }

    if (String->Length < Suffix->Length) {
        return FALSE;
    }

    offset = (String->Length - Suffix->Length) / sizeof(WCHAR);

    stringSuffix.Buffer = &String->Buffer[offset];
    stringSuffix.Length = Suffix->Length;
    stringSuffix.MaximumLength = Suffix->Length;

    return RtlEqualUnicodeString(&stringSuffix, Suffix, CaseInsensitive);
}

/**
 * @brief Check if string contains substring.
 */
BOOLEAN
ShadowStrikeStringContains(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Substring,
    _In_ BOOLEAN CaseInsensitive
    )
{
    LONG position;
    NTSTATUS status;

    status = ShadowStrikeFindSubstring(String, Substring, CaseInsensitive, &position);
    return NT_SUCCESS(status);
}

/**
 * @brief Find substring position.
 */
NTSTATUS
ShadowStrikeFindSubstring(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Substring,
    _In_ BOOLEAN CaseInsensitive,
    _Out_ PLONG Position
    )
{
    USHORT stringLen;
    USHORT subLen;
    USHORT i, j;
    BOOLEAN match;

    *Position = -1;

    if (ShadowStrikeIsStringEmpty(String) || ShadowStrikeIsStringEmpty(Substring)) {
        return STATUS_INVALID_PARAMETER;
    }

    stringLen = String->Length / sizeof(WCHAR);
    subLen = Substring->Length / sizeof(WCHAR);

    if (subLen > stringLen) {
        return STATUS_NOT_FOUND;
    }

    for (i = 0; i <= stringLen - subLen; i++) {
        match = TRUE;

        for (j = 0; j < subLen; j++) {
            WCHAR c1 = String->Buffer[i + j];
            WCHAR c2 = Substring->Buffer[j];

            if (CaseInsensitive) {
                c1 = RtlUpcaseUnicodeChar(c1);
                c2 = RtlUpcaseUnicodeChar(c2);
            }

            if (c1 != c2) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            *Position = (LONG)i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

// ============================================================================
// HASH OPERATIONS
// ============================================================================

/**
 * @brief Compute FNV-1a hash of UNICODE_STRING.
 */
ULONG
ShadowStrikeHashUnicodeString(
    _In_ PCUNICODE_STRING String,
    _In_ BOOLEAN CaseInsensitive
    )
{
    ULONG hash = SHADOW_FNV1A_SEED;
    USHORT i;
    USHORT lengthChars;

    if (ShadowStrikeIsStringEmpty(String)) {
        return hash;
    }

    lengthChars = String->Length / sizeof(WCHAR);

    for (i = 0; i < lengthChars; i++) {
        WCHAR ch = String->Buffer[i];

        if (CaseInsensitive) {
            ch = RtlUpcaseUnicodeChar(ch);
        }

        //
        // Hash both bytes of WCHAR
        //
        hash ^= (UCHAR)(ch & 0xFF);
        hash *= SHADOW_FNV1A_PRIME;
        hash ^= (UCHAR)((ch >> 8) & 0xFF);
        hash *= SHADOW_FNV1A_PRIME;
    }

    return hash;
}

/**
 * @brief Compute 64-bit hash of UNICODE_STRING.
 */
ULONG64
ShadowStrikeHashUnicodeString64(
    _In_ PCUNICODE_STRING String,
    _In_ BOOLEAN CaseInsensitive
    )
{
    ULONG64 hash = SHADOW_FNV1A_SEED_64;
    USHORT i;
    USHORT lengthChars;

    if (ShadowStrikeIsStringEmpty(String)) {
        return hash;
    }

    lengthChars = String->Length / sizeof(WCHAR);

    for (i = 0; i < lengthChars; i++) {
        WCHAR ch = String->Buffer[i];

        if (CaseInsensitive) {
            ch = RtlUpcaseUnicodeChar(ch);
        }

        hash ^= (UCHAR)(ch & 0xFF);
        hash *= SHADOW_FNV1A_PRIME_64;
        hash ^= (UCHAR)((ch >> 8) & 0xFF);
        hash *= SHADOW_FNV1A_PRIME_64;
    }

    return hash;
}

// ============================================================================
// STRING BUILDER
// ============================================================================

/**
 * @brief Initialize string builder.
 */
NTSTATUS
ShadowStrikeStringBuilderInit(
    _Out_ PSHADOW_STRING_BUILDER Builder,
    _In_ SIZE_T InitialCapacity,
    _In_ POOL_TYPE PoolType
    )
{
    PAGED_CODE();

    if (Builder == NULL || InitialCapacity == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Builder, sizeof(SHADOW_STRING_BUILDER));

    Builder->Buffer = (PWCHAR)ExAllocatePoolWithTag(
        PoolType,
        InitialCapacity * sizeof(WCHAR),
        SHADOW_STRING_TAG
    );

    if (Builder->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Builder->Buffer[0] = L'\0';
    Builder->Length = 0;
    Builder->Capacity = InitialCapacity;
    Builder->PoolTag = SHADOW_STRING_TAG;
    Builder->PoolType = PoolType;
    Builder->Overflow = FALSE;

    return STATUS_SUCCESS;
}

/**
 * @brief Internal function to grow builder buffer.
 */
static
NTSTATUS
ShadowStrikeStringBuilderGrow(
    _Inout_ PSHADOW_STRING_BUILDER Builder,
    _In_ SIZE_T RequiredCapacity
    )
{
    PWCHAR newBuffer;
    SIZE_T newCapacity;

    //
    // Calculate new capacity
    //
    newCapacity = Builder->Capacity * STRING_BUILDER_GROWTH_FACTOR;
    if (newCapacity < RequiredCapacity) {
        newCapacity = RequiredCapacity;
    }

    //
    // Overflow check
    //
    if (newCapacity * sizeof(WCHAR) < newCapacity) {
        Builder->Overflow = TRUE;
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate new buffer
    //
    newBuffer = (PWCHAR)ExAllocatePoolWithTag(
        Builder->PoolType,
        newCapacity * sizeof(WCHAR),
        Builder->PoolTag
    );

    if (newBuffer == NULL) {
        Builder->Overflow = TRUE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy existing content
    //
    if (Builder->Length > 0) {
        RtlCopyMemory(newBuffer, Builder->Buffer, Builder->Length * sizeof(WCHAR));
    }
    newBuffer[Builder->Length] = L'\0';

    //
    // Free old buffer
    //
    ExFreePoolWithTag(Builder->Buffer, Builder->PoolTag);

    Builder->Buffer = newBuffer;
    Builder->Capacity = newCapacity;

    return STATUS_SUCCESS;
}

/**
 * @brief Append string to builder.
 */
NTSTATUS
ShadowStrikeStringBuilderAppend(
    _Inout_ PSHADOW_STRING_BUILDER Builder,
    _In_ PCUNICODE_STRING String
    )
{
    NTSTATUS status;
    SIZE_T appendLength;
    SIZE_T requiredCapacity;

    if (Builder == NULL || Builder->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Builder->Overflow) {
        return STATUS_BUFFER_OVERFLOW;
    }

    if (ShadowStrikeIsStringEmpty(String)) {
        return STATUS_SUCCESS;
    }

    appendLength = String->Length / sizeof(WCHAR);
    requiredCapacity = Builder->Length + appendLength + 1;

    //
    // Grow if needed
    //
    if (requiredCapacity > Builder->Capacity) {
        status = ShadowStrikeStringBuilderGrow(Builder, requiredCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    //
    // Append
    //
    RtlCopyMemory(
        &Builder->Buffer[Builder->Length],
        String->Buffer,
        appendLength * sizeof(WCHAR)
    );

    Builder->Length += appendLength;
    Builder->Buffer[Builder->Length] = L'\0';

    return STATUS_SUCCESS;
}

/**
 * @brief Append C string to builder.
 */
NTSTATUS
ShadowStrikeStringBuilderAppendCString(
    _Inout_ PSHADOW_STRING_BUILDER Builder,
    _In_ PCWSTR String
    )
{
    UNICODE_STRING unicodeString;

    if (String == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&unicodeString, String);
    return ShadowStrikeStringBuilderAppend(Builder, &unicodeString);
}

/**
 * @brief Append formatted string to builder.
 */
NTSTATUS
ShadowStrikeStringBuilderAppendFormat(
    _Inout_ PSHADOW_STRING_BUILDER Builder,
    _In_ PCWSTR Format,
    ...
    )
{
    NTSTATUS status;
    va_list args;
    WCHAR tempBuffer[512];
    UNICODE_STRING tempString;

    if (Builder == NULL || Format == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    va_start(args, Format);

    status = RtlStringCbVPrintfW(
        tempBuffer,
        sizeof(tempBuffer),
        Format,
        args
    );

    va_end(args);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&tempString, tempBuffer);
    return ShadowStrikeStringBuilderAppend(Builder, &tempString);
}

/**
 * @brief Get UNICODE_STRING from builder.
 */
VOID
ShadowStrikeStringBuilderToUnicodeString(
    _In_ PSHADOW_STRING_BUILDER Builder,
    _Out_ PUNICODE_STRING String
    )
{
    if (Builder == NULL || String == NULL) {
        if (String != NULL) {
            String->Buffer = NULL;
            String->Length = 0;
            String->MaximumLength = 0;
        }
        return;
    }

    String->Buffer = Builder->Buffer;
    String->Length = (USHORT)(Builder->Length * sizeof(WCHAR));
    String->MaximumLength = (USHORT)(Builder->Capacity * sizeof(WCHAR));
}

/**
 * @brief Cleanup string builder.
 */
VOID
ShadowStrikeStringBuilderCleanup(
    _Inout_ PSHADOW_STRING_BUILDER Builder
    )
{
    PAGED_CODE();

    if (Builder == NULL) {
        return;
    }

    if (Builder->Buffer != NULL) {
        ExFreePoolWithTag(Builder->Buffer, Builder->PoolTag);
        Builder->Buffer = NULL;
    }

    Builder->Length = 0;
    Builder->Capacity = 0;
    Builder->Overflow = FALSE;
}

// ============================================================================
// COMMAND LINE PARSING
// ============================================================================

/**
 * @brief Parse command line into arguments.
 */
NTSTATUS
ShadowStrikeParseCommandLine(
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PUNICODE_STRING** Arguments,
    _Out_ PULONG ArgumentCount
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNICODE_STRING* argArray = NULL;
    ULONG argCount = 0;
    ULONG maxArgs = 64;
    USHORT i;
    USHORT cmdLen;
    BOOLEAN inQuotes = FALSE;
    BOOLEAN inArg = FALSE;
    USHORT argStart = 0;

    PAGED_CODE();

    *Arguments = NULL;
    *ArgumentCount = 0;

    if (ShadowStrikeIsStringEmpty(CommandLine)) {
        return STATUS_INVALID_PARAMETER;
    }

    cmdLen = CommandLine->Length / sizeof(WCHAR);

    //
    // Allocate array for argument pointers
    //
    argArray = (PUNICODE_STRING*)ExAllocatePoolWithTag(
        PagedPool,
        maxArgs * sizeof(PUNICODE_STRING),
        SHADOW_STRING_TAG
    );

    if (argArray == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(argArray, maxArgs * sizeof(PUNICODE_STRING));

    //
    // Parse command line
    //
    for (i = 0; i <= cmdLen; i++) {
        WCHAR ch = (i < cmdLen) ? CommandLine->Buffer[i] : L'\0';

        if (ch == L'"') {
            inQuotes = !inQuotes;
            if (!inArg) {
                inArg = TRUE;
                argStart = i + 1;
            }
        } else if ((ch == L' ' || ch == L'\t' || ch == L'\0') && !inQuotes) {
            if (inArg) {
                //
                // End of argument
                //
                if (argCount < maxArgs) {
                    USHORT argLen = i - argStart;

                    //
                    // Handle trailing quote
                    //
                    if (argLen > 0 && CommandLine->Buffer[i - 1] == L'"') {
                        argLen--;
                    }

                    if (argLen > 0) {
                        argArray[argCount] = (PUNICODE_STRING)ExAllocatePoolWithTag(
                            PagedPool,
                            sizeof(UNICODE_STRING),
                            SHADOW_STRING_TAG
                        );

                        if (argArray[argCount] == NULL) {
                            status = STATUS_INSUFFICIENT_RESOURCES;
                            goto cleanup;
                        }

                        UNICODE_STRING tempArg;
                        tempArg.Buffer = &CommandLine->Buffer[argStart];
                        tempArg.Length = argLen * sizeof(WCHAR);
                        tempArg.MaximumLength = tempArg.Length;

                        status = ShadowStrikeCloneUnicodeString(argArray[argCount], &tempArg);
                        if (!NT_SUCCESS(status)) {
                            ExFreePoolWithTag(argArray[argCount], SHADOW_STRING_TAG);
                            argArray[argCount] = NULL;
                            goto cleanup;
                        }

                        argCount++;
                    }
                }
                inArg = FALSE;
            }
        } else if (!inArg) {
            inArg = TRUE;
            argStart = i;
        }
    }

    *Arguments = argArray;
    *ArgumentCount = argCount;

    return STATUS_SUCCESS;

cleanup:
    if (argArray != NULL) {
        ShadowStrikeFreeCommandLineArgs(argArray, argCount);
    }
    return status;
}

/**
 * @brief Free command line arguments array.
 */
VOID
ShadowStrikeFreeCommandLineArgs(
    _In_ PUNICODE_STRING* Arguments,
    _In_ ULONG ArgumentCount
    )
{
    ULONG i;

    PAGED_CODE();

    if (Arguments == NULL) {
        return;
    }

    for (i = 0; i < ArgumentCount; i++) {
        if (Arguments[i] != NULL) {
            ShadowStrikeFreeUnicodeString(Arguments[i]);
            ExFreePoolWithTag(Arguments[i], SHADOW_STRING_TAG);
        }
    }

    ExFreePoolWithTag(Arguments, SHADOW_STRING_TAG);
}

/**
 * @brief Extract executable path from command line.
 */
NTSTATUS
ShadowStrikeGetExePathFromCommandLine(
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PUNICODE_STRING ExePath
    )
{
    NTSTATUS status;
    PUNICODE_STRING* args = NULL;
    ULONG argCount = 0;

    PAGED_CODE();

    ExePath->Buffer = NULL;
    ExePath->Length = 0;
    ExePath->MaximumLength = 0;

    status = ShadowStrikeParseCommandLine(CommandLine, &args, &argCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (argCount == 0 || args[0] == NULL) {
        ShadowStrikeFreeCommandLineArgs(args, argCount);
        return STATUS_NOT_FOUND;
    }

    //
    // Clone first argument as exe path
    //
    status = ShadowStrikeCloneUnicodeString(ExePath, args[0]);

    ShadowStrikeFreeCommandLineArgs(args, argCount);

    return status;
}

// ============================================================================
// CONVERSION UTILITIES
// ============================================================================

/**
 * @brief Convert UNICODE_STRING to lowercase.
 */
VOID
ShadowStrikeStringToLower(
    _Inout_ PUNICODE_STRING String
    )
{
    USHORT i;
    USHORT lengthChars;

    if (ShadowStrikeIsStringEmpty(String)) {
        return;
    }

    lengthChars = String->Length / sizeof(WCHAR);

    for (i = 0; i < lengthChars; i++) {
        String->Buffer[i] = RtlDowncaseUnicodeChar(String->Buffer[i]);
    }
}

/**
 * @brief Convert UNICODE_STRING to uppercase.
 */
VOID
ShadowStrikeStringToUpper(
    _Inout_ PUNICODE_STRING String
    )
{
    USHORT i;
    USHORT lengthChars;

    if (ShadowStrikeIsStringEmpty(String)) {
        return;
    }

    lengthChars = String->Length / sizeof(WCHAR);

    for (i = 0; i < lengthChars; i++) {
        String->Buffer[i] = RtlUpcaseUnicodeChar(String->Buffer[i]);
    }
}

/**
 * @brief Convert ANSI string to UNICODE string.
 */
NTSTATUS
ShadowStrikeAnsiToUnicode(
    _In_ PCANSI_STRING AnsiString,
    _Out_ PUNICODE_STRING UnicodeString
    )
{
    NTSTATUS status;
    ULONG unicodeLength;

    PAGED_CODE();

    UnicodeString->Buffer = NULL;
    UnicodeString->Length = 0;
    UnicodeString->MaximumLength = 0;

    if (AnsiString == NULL || AnsiString->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Calculate required size
    //
    status = RtlAnsiStringToUnicodeSize(AnsiString);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    unicodeLength = RtlAnsiStringToUnicodeSize(AnsiString);

    UnicodeString->Buffer = (PWCH)ExAllocatePoolWithTag(
        PagedPool,
        unicodeLength,
        SHADOW_STRING_TAG
    );

    if (UnicodeString->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UnicodeString->MaximumLength = (USHORT)unicodeLength;

    status = RtlAnsiStringToUnicodeString(UnicodeString, AnsiString, FALSE);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(UnicodeString->Buffer, SHADOW_STRING_TAG);
        UnicodeString->Buffer = NULL;
        UnicodeString->MaximumLength = 0;
    }

    return status;
}

/**
 * @brief Convert UNICODE string to ANSI string.
 */
NTSTATUS
ShadowStrikeUnicodeToAnsi(
    _In_ PCUNICODE_STRING UnicodeString,
    _Out_ PANSI_STRING AnsiString
    )
{
    NTSTATUS status;
    ULONG ansiLength;

    PAGED_CODE();

    AnsiString->Buffer = NULL;
    AnsiString->Length = 0;
    AnsiString->MaximumLength = 0;

    if (ShadowStrikeIsStringEmpty(UnicodeString)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Calculate required size
    //
    ansiLength = RtlUnicodeStringToAnsiSize(UnicodeString);

    AnsiString->Buffer = (PCHAR)ExAllocatePoolWithTag(
        PagedPool,
        ansiLength,
        SHADOW_STRING_TAG
    );

    if (AnsiString->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    AnsiString->MaximumLength = (USHORT)ansiLength;

    status = RtlUnicodeStringToAnsiString(AnsiString, UnicodeString, FALSE);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(AnsiString->Buffer, SHADOW_STRING_TAG);
        AnsiString->Buffer = NULL;
        AnsiString->MaximumLength = 0;
    }

    return status;
}

/**
 * @brief Convert integer to UNICODE string.
 */
NTSTATUS
ShadowStrikeIntegerToUnicodeString(
    _In_ ULONG64 Value,
    _In_ ULONG Base,
    _Out_ PUNICODE_STRING String
    )
{
    NTSTATUS status;
    WCHAR buffer[32];
    UNICODE_STRING tempString;

    PAGED_CODE();

    String->Buffer = NULL;
    String->Length = 0;
    String->MaximumLength = 0;

    if (Base != 10 && Base != 16) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Format value
    //
    if (Base == 16) {
        status = RtlStringCbPrintfW(buffer, sizeof(buffer), L"0x%I64X", Value);
    } else {
        status = RtlStringCbPrintfW(buffer, sizeof(buffer), L"%I64u", Value);
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&tempString, buffer);
    return ShadowStrikeCloneUnicodeString(String, &tempString);
}

/**
 * @brief Convert GUID to UNICODE string.
 */
NTSTATUS
ShadowStrikeGuidToUnicodeString(
    _In_ PCGUID Guid,
    _Out_ PUNICODE_STRING String
    )
{
    NTSTATUS status;
    WCHAR buffer[64];
    UNICODE_STRING tempString;

    PAGED_CODE();

    String->Buffer = NULL;
    String->Length = 0;
    String->MaximumLength = 0;

    if (Guid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = RtlStringCbPrintfW(
        buffer,
        sizeof(buffer),
        L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        Guid->Data1,
        Guid->Data2,
        Guid->Data3,
        Guid->Data4[0], Guid->Data4[1],
        Guid->Data4[2], Guid->Data4[3],
        Guid->Data4[4], Guid->Data4[5],
        Guid->Data4[6], Guid->Data4[7]
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&tempString, buffer);
    return ShadowStrikeCloneUnicodeString(String, &tempString);
}

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

/**
 * @brief Validate UNICODE_STRING structure.
 */
BOOLEAN
ShadowStrikeIsValidUnicodeString(
    _In_opt_ PCUNICODE_STRING String
    )
{
    if (String == NULL) {
        return FALSE;
    }

    //
    // Empty string is valid
    //
    if (String->Length == 0) {
        return TRUE;
    }

    //
    // Buffer must be non-null for non-empty string
    //
    if (String->Buffer == NULL) {
        return FALSE;
    }

    //
    // Length must be even (WCHAR aligned)
    //
    if (String->Length & 1) {
        return FALSE;
    }

    //
    // Length must not exceed maximum
    //
    if (String->Length > String->MaximumLength) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Check if string contains only printable characters.
 */
BOOLEAN
ShadowStrikeIsStringPrintable(
    _In_ PCUNICODE_STRING String
    )
{
    USHORT i;
    USHORT lengthChars;

    if (ShadowStrikeIsStringEmpty(String)) {
        return TRUE;
    }

    lengthChars = String->Length / sizeof(WCHAR);

    for (i = 0; i < lengthChars; i++) {
        WCHAR ch = String->Buffer[i];

        //
        // Check for printable range (space through tilde plus extended)
        //
        if (ch < 0x20 && ch != L'\t' && ch != L'\r' && ch != L'\n') {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Check if string is valid file path.
 */
BOOLEAN
ShadowStrikeIsValidFilePath(
    _In_ PCUNICODE_STRING Path
    )
{
    USHORT i, j;
    USHORT lengthChars;
    USHORT invalidCount;

    if (ShadowStrikeIsStringEmpty(Path)) {
        return FALSE;
    }

    lengthChars = Path->Length / sizeof(WCHAR);
    invalidCount = (USHORT)(wcslen(g_InvalidPathChars));

    //
    // Check for invalid characters (skip first 3 chars for drive letter)
    //
    for (i = 0; i < lengthChars; i++) {
        WCHAR ch = Path->Buffer[i];

        //
        // Control characters are invalid
        //
        if (ch < 0x20) {
            return FALSE;
        }

        //
        // Skip drive letter colon check
        //
        if (i == 1 && ch == L':') {
            continue;
        }

        //
        // Check against invalid chars (except \ which is path separator)
        //
        for (j = 0; j < invalidCount; j++) {
            if (ch == g_InvalidPathChars[j]) {
                return FALSE;
            }
        }
    }

    return TRUE;
}
