/**
 * ============================================================================
 * ShadowStrike NGAV - STRING UTILITIES
 * ============================================================================
 *
 * @file StringUtils.h
 * @brief Enterprise-grade string manipulation for kernel-mode EDR operations.
 *
 * Provides CrowdStrike Falcon-level string handling with:
 * - Safe UNICODE_STRING manipulation (no buffer overflows)
 * - Path parsing and normalization (DOS/NT path conversion)
 * - Wildcard pattern matching (file exclusions, IOC matching)
 * - Case-insensitive comparison with locale awareness
 * - Hash computation for string deduplication
 * - Memory-safe string builders
 * - File extension extraction
 * - Process name parsing
 * - Registry path manipulation
 * - Command-line argument parsing
 *
 * Security Guarantees:
 * - All functions validate input parameters
 * - Buffer sizes are always checked before operations
 * - No integer overflows in length calculations
 * - Null terminators enforced where appropriate
 * - Pool allocations use tagged pools for leak detection
 *
 * Performance Optimizations:
 * - Inline functions for hot paths
 * - Lookaside list support for common allocations
 * - Zero-copy operations where possible
 * - IRQL-aware implementations
 *
 * MITRE ATT&CK Coverage:
 * - T1036: Masquerading (path normalization detects tricks)
 * - T1027: Obfuscated Files (Unicode normalization)
 * - T1055: Process Injection (command-line parsing)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_STRING_UTILS_H_
#define _SHADOWSTRIKE_STRING_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>
#include <ntstrsafe.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for string allocations: 'sSSx' = ShadowStrike String
 */
#define SHADOW_STRING_TAG 'sSSx'

/**
 * @brief Pool tag for path allocations
 */
#define SHADOW_PATH_TAG 'pSSx'

/**
 * @brief Pool tag for pattern allocations
 */
#define SHADOW_PATTERN_TAG 'tSSx'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum path length in characters
 */
#define SHADOW_MAX_PATH 32767

/**
 * @brief Maximum file name length in characters
 */
#define SHADOW_MAX_FILENAME 255

/**
 * @brief Maximum extension length in characters (including dot)
 */
#define SHADOW_MAX_EXTENSION 32

/**
 * @brief Maximum command-line length in characters
 */
#define SHADOW_MAX_CMDLINE 32767

/**
 * @brief Maximum registry path length
 */
#define SHADOW_MAX_REGISTRY_PATH 512

/**
 * @brief FNV-1a hash seed
 */
#define SHADOW_FNV1A_SEED 0x811c9dc5UL

/**
 * @brief FNV-1a hash prime
 */
#define SHADOW_FNV1A_PRIME 0x01000193UL

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Path type enumeration
 */
typedef enum _SHADOW_PATH_TYPE {
    ShadowPathUnknown = 0,
    ShadowPathDos,              ///< C:\Windows\System32
    ShadowPathNt,               ///< \Device\HarddiskVolume1\Windows
    ShadowPathUNC,              ///< \\Server\Share\Path
    ShadowPathDevice,           ///< \\.\DeviceName
    ShadowPathRegistry,         ///< \REGISTRY\MACHINE\SOFTWARE
    ShadowPathRelative          ///< Relative path
} SHADOW_PATH_TYPE;

/**
 * @brief Pattern match result
 */
typedef enum _SHADOW_MATCH_RESULT {
    ShadowMatchNone = 0,        ///< No match
    ShadowMatchExact,           ///< Exact match
    ShadowMatchWildcard,        ///< Wildcard match
    ShadowMatchPrefix,          ///< Prefix match
    ShadowMatchSuffix           ///< Suffix match
} SHADOW_MATCH_RESULT;

// ============================================================================
// STRING BUILDER STRUCTURE
// ============================================================================

/**
 * @brief Dynamic string builder for efficient concatenation
 */
typedef struct _SHADOW_STRING_BUILDER {
    PWCHAR Buffer;              ///< String buffer
    SIZE_T Length;              ///< Current length in characters (excluding null)
    SIZE_T Capacity;            ///< Buffer capacity in characters
    ULONG PoolTag;              ///< Pool tag for allocations
    POOL_TYPE PoolType;         ///< Pool type (Paged/NonPaged)
    BOOLEAN Overflow;           ///< TRUE if overflow occurred
} SHADOW_STRING_BUILDER, *PSHADOW_STRING_BUILDER;

// ============================================================================
// BASIC STRING OPERATIONS
// ============================================================================

/**
 * @brief Copy UNICODE_STRING with bounds checking.
 *
 * @param Destination   Destination string (must have allocated buffer)
 * @param Source        Source string to copy
 *
 * @return STATUS_SUCCESS or STATUS_BUFFER_TOO_SMALL
 *
 * @irql <= DISPATCH_LEVEL (if buffers are non-paged)
 */
NTSTATUS
ShadowStrikeCopyUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

/**
 * @brief Append UNICODE_STRING with bounds checking.
 *
 * @param Destination   Destination string
 * @param Source        Source string to append
 *
 * @return STATUS_SUCCESS or STATUS_BUFFER_TOO_SMALL
 *
 * @irql <= DISPATCH_LEVEL (if buffers are non-paged)
 */
NTSTATUS
ShadowStrikeAppendUnicodeString(
    _Inout_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

/**
 * @brief Clone UNICODE_STRING with new allocation.
 *
 * Allocates new buffer and copies source string.
 * Caller must free with ShadowStrikeFreeUnicodeString.
 *
 * @param Destination   Receives cloned string
 * @param Source        Source string to clone
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeCloneUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

/**
 * @brief Clone UNICODE_STRING to non-paged pool.
 *
 * For use in callbacks that may run at DISPATCH_LEVEL.
 *
 * @param Destination   Receives cloned string
 * @param Source        Source string to clone
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
ShadowStrikeCloneUnicodeStringNonPaged(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

/**
 * @brief Free UNICODE_STRING allocated by ShadowStrikeCloneUnicodeString.
 *
 * @param String    String to free
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowStrikeFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    );

/**
 * @brief Compare two UNICODE_STRINGs for equality.
 *
 * @param String1           First string
 * @param String2           Second string
 * @param CaseInsensitive   TRUE for case-insensitive comparison
 *
 * @return TRUE if strings are equal
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsStringMatch(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN CaseInsensitive
    );

/**
 * @brief Compare UNICODE_STRING with C string.
 *
 * @param String            UNICODE_STRING to compare
 * @param CString           Null-terminated wide string
 * @param CaseInsensitive   TRUE for case-insensitive comparison
 *
 * @return TRUE if strings are equal
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeCompareStringToCString(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR CString,
    _In_ BOOLEAN CaseInsensitive
    );

// ============================================================================
// PATH OPERATIONS
// ============================================================================

/**
 * @brief Determine path type (DOS, NT, UNC, etc.)
 *
 * @param Path      Path to analyze
 *
 * @return Path type enumeration
 *
 * @irql <= DISPATCH_LEVEL
 */
SHADOW_PATH_TYPE
ShadowStrikeGetPathType(
    _In_ PCUNICODE_STRING Path
    );

/**
 * @brief Extract file name from path.
 *
 * Returns pointer to the filename portion within the input string.
 * Does not allocate memory.
 *
 * @param FullPath      Full path string
 * @param FileName      Receives filename portion (points into FullPath buffer)
 *
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    );

/**
 * @brief Extract file extension from path.
 *
 * @param FullPath      Full path or filename
 * @param Extension     Receives extension (including dot)
 *
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND if no extension
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
ShadowStrikeGetFileExtension(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING Extension
    );

/**
 * @brief Extract directory path from full path.
 *
 * @param FullPath      Full path
 * @param Directory     Receives directory portion (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetDirectoryPath(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING Directory
    );

/**
 * @brief Normalize path (resolve . and .., convert separators)
 *
 * @param InputPath     Input path
 * @param NormalizedPath Receives normalized path (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeNormalizePath(
    _In_ PCUNICODE_STRING InputPath,
    _Out_ PUNICODE_STRING NormalizedPath
    );

/**
 * @brief Convert DOS path to NT path.
 *
 * Converts C:\Windows to \Device\HarddiskVolume1\Windows
 *
 * @param DosPath       DOS-style path
 * @param NtPath        Receives NT path (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeDosPathToNtPath(
    _In_ PCUNICODE_STRING DosPath,
    _Out_ PUNICODE_STRING NtPath
    );

/**
 * @brief Convert NT path to DOS path.
 *
 * Converts \Device\HarddiskVolume1\Windows to C:\Windows
 *
 * @param NtPath        NT-style path
 * @param DosPath       Receives DOS path (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeNtPathToDosPath(
    _In_ PCUNICODE_STRING NtPath,
    _Out_ PUNICODE_STRING DosPath
    );

/**
 * @brief Check if path is under a specific directory.
 *
 * @param Path              Path to check
 * @param DirectoryPath     Directory to check against
 * @param CaseInsensitive   TRUE for case-insensitive comparison
 *
 * @return TRUE if path is under directory
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsPathUnderDirectory(
    _In_ PCUNICODE_STRING Path,
    _In_ PCUNICODE_STRING DirectoryPath,
    _In_ BOOLEAN CaseInsensitive
    );

// ============================================================================
// PATTERN MATCHING
// ============================================================================

/**
 * @brief Match string against wildcard pattern.
 *
 * Supports * (any characters) and ? (single character) wildcards.
 *
 * @param String            String to match
 * @param Pattern           Pattern with wildcards
 * @param CaseInsensitive   TRUE for case-insensitive matching
 *
 * @return Match result enumeration
 *
 * @irql <= DISPATCH_LEVEL
 */
SHADOW_MATCH_RESULT
ShadowStrikeMatchWildcard(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Pattern,
    _In_ BOOLEAN CaseInsensitive
    );

/**
 * @brief Check if string starts with prefix.
 *
 * @param String            String to check
 * @param Prefix            Prefix to match
 * @param CaseInsensitive   TRUE for case-insensitive comparison
 *
 * @return TRUE if string starts with prefix
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeStringStartsWith(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Prefix,
    _In_ BOOLEAN CaseInsensitive
    );

/**
 * @brief Check if string ends with suffix.
 *
 * @param String            String to check
 * @param Suffix            Suffix to match
 * @param CaseInsensitive   TRUE for case-insensitive comparison
 *
 * @return TRUE if string ends with suffix
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeStringEndsWith(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Suffix,
    _In_ BOOLEAN CaseInsensitive
    );

/**
 * @brief Check if string contains substring.
 *
 * @param String            String to search
 * @param Substring         Substring to find
 * @param CaseInsensitive   TRUE for case-insensitive search
 *
 * @return TRUE if substring found
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeStringContains(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Substring,
    _In_ BOOLEAN CaseInsensitive
    );

/**
 * @brief Find substring position.
 *
 * @param String            String to search
 * @param Substring         Substring to find
 * @param CaseInsensitive   TRUE for case-insensitive search
 * @param Position          Receives character position (or -1 if not found)
 *
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
NTSTATUS
ShadowStrikeFindSubstring(
    _In_ PCUNICODE_STRING String,
    _In_ PCUNICODE_STRING Substring,
    _In_ BOOLEAN CaseInsensitive,
    _Out_ PLONG Position
    );

// ============================================================================
// HASH OPERATIONS
// ============================================================================

/**
 * @brief Compute FNV-1a hash of UNICODE_STRING.
 *
 * @param String            String to hash
 * @param CaseInsensitive   TRUE for case-insensitive hashing
 *
 * @return 32-bit hash value
 *
 * @irql <= DISPATCH_LEVEL
 */
ULONG
ShadowStrikeHashUnicodeString(
    _In_ PCUNICODE_STRING String,
    _In_ BOOLEAN CaseInsensitive
    );

/**
 * @brief Compute 64-bit hash of UNICODE_STRING.
 *
 * @param String            String to hash
 * @param CaseInsensitive   TRUE for case-insensitive hashing
 *
 * @return 64-bit hash value
 *
 * @irql <= DISPATCH_LEVEL
 */
ULONG64
ShadowStrikeHashUnicodeString64(
    _In_ PCUNICODE_STRING String,
    _In_ BOOLEAN CaseInsensitive
    );

// ============================================================================
// STRING BUILDER
// ============================================================================

/**
 * @brief Initialize string builder.
 *
 * @param Builder       String builder to initialize
 * @param InitialCapacity   Initial capacity in characters
 * @param PoolType      Pool type for allocations
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES
 *
 * @irql PASSIVE_LEVEL (for paged pool)
 */
NTSTATUS
ShadowStrikeStringBuilderInit(
    _Out_ PSHADOW_STRING_BUILDER Builder,
    _In_ SIZE_T InitialCapacity,
    _In_ POOL_TYPE PoolType
    );

/**
 * @brief Append string to builder.
 *
 * @param Builder       String builder
 * @param String        String to append
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql Depends on pool type
 */
NTSTATUS
ShadowStrikeStringBuilderAppend(
    _Inout_ PSHADOW_STRING_BUILDER Builder,
    _In_ PCUNICODE_STRING String
    );

/**
 * @brief Append C string to builder.
 *
 * @param Builder       String builder
 * @param String        Null-terminated string to append
 *
 * @return STATUS_SUCCESS or error
 */
NTSTATUS
ShadowStrikeStringBuilderAppendCString(
    _Inout_ PSHADOW_STRING_BUILDER Builder,
    _In_ PCWSTR String
    );

/**
 * @brief Append formatted string to builder.
 *
 * @param Builder       String builder
 * @param Format        Format string
 * @param ...           Format arguments
 *
 * @return STATUS_SUCCESS or error
 */
NTSTATUS
ShadowStrikeStringBuilderAppendFormat(
    _Inout_ PSHADOW_STRING_BUILDER Builder,
    _In_ PCWSTR Format,
    ...
    );

/**
 * @brief Get UNICODE_STRING from builder (no allocation).
 *
 * @param Builder       String builder
 * @param String        Receives UNICODE_STRING pointing to builder buffer
 */
VOID
ShadowStrikeStringBuilderToUnicodeString(
    _In_ PSHADOW_STRING_BUILDER Builder,
    _Out_ PUNICODE_STRING String
    );

/**
 * @brief Cleanup string builder.
 *
 * @param Builder       String builder to cleanup
 */
VOID
ShadowStrikeStringBuilderCleanup(
    _Inout_ PSHADOW_STRING_BUILDER Builder
    );

// ============================================================================
// COMMAND LINE PARSING
// ============================================================================

/**
 * @brief Parse command line into arguments.
 *
 * Handles quoted arguments and escaped characters.
 *
 * @param CommandLine   Full command line string
 * @param Arguments     Receives array of argument strings
 * @param ArgumentCount Receives number of arguments
 *
 * @return STATUS_SUCCESS or error
 *
 * @note Caller must free Arguments array with ShadowStrikeFreeCommandLineArgs
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeParseCommandLine(
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PUNICODE_STRING** Arguments,
    _Out_ PULONG ArgumentCount
    );

/**
 * @brief Free command line arguments array.
 *
 * @param Arguments     Argument array from ShadowStrikeParseCommandLine
 * @param ArgumentCount Number of arguments
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowStrikeFreeCommandLineArgs(
    _In_ PUNICODE_STRING* Arguments,
    _In_ ULONG ArgumentCount
    );

/**
 * @brief Extract executable path from command line.
 *
 * @param CommandLine   Full command line
 * @param ExePath       Receives executable path (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGetExePathFromCommandLine(
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PUNICODE_STRING ExePath
    );

// ============================================================================
// CONVERSION UTILITIES
// ============================================================================

/**
 * @brief Convert UNICODE_STRING to lowercase.
 *
 * Modifies string in place.
 *
 * @param String    String to convert
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowStrikeStringToLower(
    _Inout_ PUNICODE_STRING String
    );

/**
 * @brief Convert UNICODE_STRING to uppercase.
 *
 * Modifies string in place.
 *
 * @param String    String to convert
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowStrikeStringToUpper(
    _Inout_ PUNICODE_STRING String
    );

/**
 * @brief Convert ANSI string to UNICODE string.
 *
 * @param AnsiString    ANSI string input
 * @param UnicodeString Receives UNICODE string (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeAnsiToUnicode(
    _In_ PCANSI_STRING AnsiString,
    _Out_ PUNICODE_STRING UnicodeString
    );

/**
 * @brief Convert UNICODE string to ANSI string.
 *
 * @param UnicodeString UNICODE string input
 * @param AnsiString    Receives ANSI string (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeUnicodeToAnsi(
    _In_ PCUNICODE_STRING UnicodeString,
    _Out_ PANSI_STRING AnsiString
    );

/**
 * @brief Convert integer to UNICODE string.
 *
 * @param Value         Integer value
 * @param Base          Numeric base (10 or 16)
 * @param String        Receives string representation (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeIntegerToUnicodeString(
    _In_ ULONG64 Value,
    _In_ ULONG Base,
    _Out_ PUNICODE_STRING String
    );

/**
 * @brief Convert GUID to UNICODE string.
 *
 * @param Guid          GUID to convert
 * @param String        Receives string representation (allocates new buffer)
 *
 * @return STATUS_SUCCESS or error
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowStrikeGuidToUnicodeString(
    _In_ PCGUID Guid,
    _Out_ PUNICODE_STRING String
    );

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

/**
 * @brief Validate UNICODE_STRING structure.
 *
 * Checks for proper length, buffer pointer, and null termination.
 *
 * @param String    String to validate
 *
 * @return TRUE if valid, FALSE otherwise
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsValidUnicodeString(
    _In_opt_ PCUNICODE_STRING String
    );

/**
 * @brief Check if string contains only printable characters.
 *
 * @param String    String to check
 *
 * @return TRUE if all characters are printable
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsStringPrintable(
    _In_ PCUNICODE_STRING String
    );

/**
 * @brief Check if string is valid file path.
 *
 * Checks for invalid path characters.
 *
 * @param Path      Path to validate
 *
 * @return TRUE if valid path
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowStrikeIsValidFilePath(
    _In_ PCUNICODE_STRING Path
    );

// ============================================================================
// INLINE FUNCTIONS
// ============================================================================

/**
 * @brief Get string length in characters (not bytes).
 */
FORCEINLINE
USHORT
ShadowStrikeStringLengthChars(
    _In_ PCUNICODE_STRING String
    )
{
    if (String == NULL || String->Buffer == NULL) {
        return 0;
    }
    return String->Length / sizeof(WCHAR);
}

/**
 * @brief Check if UNICODE_STRING is empty.
 */
FORCEINLINE
BOOLEAN
ShadowStrikeIsStringEmpty(
    _In_opt_ PCUNICODE_STRING String
    )
{
    return (String == NULL || String->Buffer == NULL || String->Length == 0);
}

/**
 * @brief Initialize UNICODE_STRING from C string (no allocation).
 */
FORCEINLINE
VOID
ShadowStrikeInitUnicodeString(
    _Out_ PUNICODE_STRING String,
    _In_opt_ PCWSTR Source
    )
{
    RtlInitUnicodeString(String, Source);
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_STRING_UTILS_H_
