#pragma once
/**
 * @file PEValidation.hpp
 * @brief PE validation utilities with detailed error reporting.
 *
 * Provides comprehensive validation for all PE structures with:
 * - Specific error codes for each failure mode
 * - Bounds checking for all fields
 * - Overlap detection for sections
 * - Anomaly detection for malware analysis
 *
 * @copyright ShadowStrike Security Suite
 */

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

#include "PEConstants.hpp"
#include "PETypes.hpp"
#include "SafeReader.hpp"

namespace ShadowStrike {
namespace PEParser {

// ============================================================================
// Validation Result Codes
// ============================================================================

/**
 * @brief Detailed validation result codes for PE parsing.
 *
 * Each code identifies a specific validation failure, enabling
 * precise error reporting and forensic analysis.
 */
enum class ValidationResult : uint32_t {
    Valid = 0,

    // General errors (1-9)
    UnknownError = 1,
    FileTooSmall = 2,
    FileTooLarge = 3,
    NullPointer = 4,
    IntegerOverflow = 5,

    // DOS Header failures (10-29)
    InvalidDosSignature = 10,
    InvalidLfanew = 11,
    LfanewOutOfBounds = 12,
    LfanewNegative = 13,
    LfanewUnaligned = 14,
    LfanewTooSmall = 15,
    LfanewTooLarge = 16,

    // NT Headers failures (30-59)
    InvalidNtSignature = 30,
    InvalidMachine = 31,
    InvalidOptionalMagic = 32,
    NumberOfSectionsZero = 33,
    NumberOfSectionsOverflow = 34,
    SizeOfOptionalHeaderInvalid = 35,
    SizeOfOptionalHeaderTooSmall = 36,
    SizeOfOptionalHeaderTooLarge = 37,
    NtHeadersOutOfBounds = 38,
    InvalidFileAlignment = 39,
    InvalidSectionAlignment = 40,
    FileAlignmentGreaterThanSection = 41,
    SizeOfImageZero = 42,
    SizeOfHeadersZero = 43,
    SizeOfHeadersTooLarge = 44,
    NumberOfRvaAndSizesInvalid = 45,
    InvalidAddressOfEntryPoint = 46,
    InvalidImageBase = 47,
    InvalidSubsystem = 48,

    // Section failures (60-99)
    SectionTableOutOfBounds = 60,
    SectionTableOverflow = 61,
    SectionCountMismatch = 62,
    SectionNameInvalid = 63,
    SectionVirtualAddressZero = 64,
    SectionVirtualSizeZero = 65,
    SectionRawAddressInvalid = 66,
    SectionRawSizeInvalid = 67,
    SectionBeyondFile = 68,
    SectionBeyondImage = 69,
    SectionOverlap = 70,
    SectionAlignmentViolation = 71,
    SectionCharacteristicsInvalid = 72,
    SectionWritableExecutable = 73,  // W+X is suspicious
    EntryPointOutsideSections = 74,
    EntryPointInNonExecutable = 75,

    // Data Directory failures (100-129)
    DataDirectoryOutOfBounds = 100,
    DataDirectorySizeInvalid = 101,
    DataDirectoryRvaInvalid = 102,
    ImportDirectoryInvalid = 103,
    ExportDirectoryInvalid = 104,
    ResourceDirectoryInvalid = 105,
    TLSDirectoryInvalid = 106,
    RelocDirectoryInvalid = 107,
    DebugDirectoryInvalid = 108,
    SecurityDirectoryInvalid = 109,
    CLRDirectoryInvalid = 110,
    BoundImportInvalid = 111,
    DelayImportInvalid = 112,
    LoadConfigInvalid = 113,

    // Import table failures (130-159)
    ImportDescriptorOutOfBounds = 130,
    ImportDllNameOutOfBounds = 131,
    ImportDllNameTooLong = 132,
    ImportThunkOutOfBounds = 133,
    ImportByNameOutOfBounds = 134,
    ImportFunctionNameTooLong = 135,
    ImportOrdinalInvalid = 136,
    ImportCircularReference = 137,
    ImportCountExceeded = 138,

    // Export table failures (160-179)
    ExportDirectoryOutOfBounds = 160,
    ExportNameOutOfBounds = 161,
    ExportOrdinalOutOfBounds = 162,
    ExportAddressOutOfBounds = 163,
    ExportForwarderInvalid = 164,
    ExportCountExceeded = 165,

    // TLS failures (180-199)
    TLSDirectoryOutOfBounds = 180,
    TLSCallbacksOutOfBounds = 181,
    TLSCallbackCountExceeded = 182,
    TLSDataOutOfBounds = 183,
    TLSCallbackInNonExecutable = 184,

    // Resource failures (200-229)
    ResourceDirectoryOutOfBounds = 200,
    ResourceDepthExceeded = 201,
    ResourceCircularReference = 202,
    ResourceEntryCountExceeded = 203,
    ResourceDataOutOfBounds = 204,
    ResourceNameOutOfBounds = 205,

    // Relocation failures (230-249)
    RelocationBlockOutOfBounds = 230,
    RelocationBlockSizeInvalid = 231,
    RelocationEntryInvalid = 232,
    RelocationCountExceeded = 233,
    RelocationCircularReference = 234,

    // Debug directory failures (250-269)
    DebugEntryOutOfBounds = 250,
    DebugDataOutOfBounds = 251,
    DebugCountExceeded = 252,
    DebugTypeUnknown = 253,

    // Rich header failures (270-289)
    RichHeaderNotFound = 270,
    RichHeaderCorrupted = 271,
    RichHeaderChecksumMismatch = 272,
    RichEntryCountExceeded = 273,

    // Authenticode failures (290-309)
    SignatureDirectoryInvalid = 290,
    SignatureOutOfBounds = 291,
    SignatureFormatInvalid = 292,
};

/**
 * @brief Convert validation result to string.
 * @param result Validation result code.
 * @return Human-readable description.
 */
[[nodiscard]] const wchar_t* ValidationResultToString(ValidationResult result) noexcept;

// ============================================================================
// Error Structure
// ============================================================================

/**
 * @brief Detailed error information for PE parsing operations.
 */
struct PEError {
    ValidationResult code = ValidationResult::Valid;
    std::wstring message;
    uint64_t offset = 0;      ///< File offset where error occurred
    std::wstring context;     ///< What was being parsed
    uint32_t win32Error = 0;  ///< Windows error code if applicable

    /**
     * @brief Check if an error occurred.
     */
    [[nodiscard]] bool HasError() const noexcept {
        return code != ValidationResult::Valid;
    }

    /**
     * @brief Clear error state.
     */
    void Clear() noexcept {
        code = ValidationResult::Valid;
        message.clear();
        offset = 0;
        context.clear();
        win32Error = 0;
    }

    /**
     * @brief Set error with message.
     */
    void Set(ValidationResult c, const wchar_t* msg, uint64_t off = 0) noexcept {
        code = c;
        if (msg) message = msg;
        offset = off;
    }

    /**
     * @brief Set error with context.
     */
    void SetWithContext(ValidationResult c, const wchar_t* msg,
                        const wchar_t* ctx, uint64_t off = 0) noexcept {
        code = c;
        if (msg) message = msg;
        if (ctx) context = ctx;
        offset = off;
    }
};

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * @brief Validate DOS header.
 * @param reader Safe reader positioned at file start.
 * @param outLfanew Output for e_lfanew value if valid.
 * @param err Optional error output.
 * @return Validation result.
 */
[[nodiscard]] ValidationResult ValidateDosHeader(
    const SafeReader& reader,
    int32_t& outLfanew,
    PEError* err = nullptr) noexcept;

/**
 * @brief Validate NT headers signature and file header.
 * @param reader Safe reader.
 * @param ntOffset Offset of NT headers (from e_lfanew).
 * @param outIs64Bit Output for architecture detection.
 * @param outFileHeader Output for file header.
 * @param err Optional error output.
 * @return Validation result.
 */
[[nodiscard]] ValidationResult ValidateNtHeaders(
    const SafeReader& reader,
    size_t ntOffset,
    bool& outIs64Bit,
    FileHeader& outFileHeader,
    PEError* err = nullptr) noexcept;

/**
 * @brief Validate PE32 optional header.
 * @param reader Safe reader.
 * @param offset Offset of optional header.
 * @param sizeOfOptionalHeader Size from file header.
 * @param outOptional Output for optional header.
 * @param err Optional error output.
 * @return Validation result.
 */
[[nodiscard]] ValidationResult ValidateOptionalHeader32(
    const SafeReader& reader,
    size_t offset,
    uint16_t sizeOfOptionalHeader,
    OptionalHeader32& outOptional,
    PEError* err = nullptr) noexcept;

/**
 * @brief Validate PE64 optional header.
 * @param reader Safe reader.
 * @param offset Offset of optional header.
 * @param sizeOfOptionalHeader Size from file header.
 * @param outOptional Output for optional header.
 * @param err Optional error output.
 * @return Validation result.
 */
[[nodiscard]] ValidationResult ValidateOptionalHeader64(
    const SafeReader& reader,
    size_t offset,
    uint16_t sizeOfOptionalHeader,
    OptionalHeader64& outOptional,
    PEError* err = nullptr) noexcept;

/**
 * @brief Validate a single section header.
 * @param header Section header to validate.
 * @param fileSize Size of the PE file.
 * @param sizeOfImage Expected size of image in memory.
 * @param fileAlignment File alignment from optional header.
 * @param sectionIndex Index of section (for error reporting).
 * @param err Optional error output.
 * @return Validation result.
 */
[[nodiscard]] ValidationResult ValidateSectionHeader(
    const SectionHeader& header,
    size_t fileSize,
    uint32_t sizeOfImage,
    uint32_t fileAlignment,
    size_t sectionIndex,
    PEError* err = nullptr) noexcept;

/**
 * @brief Check for overlapping sections.
 * @param sections Vector of section headers.
 * @param outOverlaps Output pairs of overlapping section indices.
 * @return true if any overlaps detected.
 */
[[nodiscard]] bool CheckSectionOverlaps(
    const std::vector<SectionHeader>& sections,
    std::vector<std::pair<size_t, size_t>>& outOverlaps) noexcept;

/**
 * @brief Validate data directory entry.
 * @param index Data directory index.
 * @param rva RVA of the directory.
 * @param size Size of the directory.
 * @param fileSize Size of the PE file.
 * @param err Optional error output.
 * @return Validation result.
 */
[[nodiscard]] ValidationResult ValidateDataDirectory(
    size_t index,
    uint32_t rva,
    uint32_t size,
    size_t fileSize,
    PEError* err = nullptr) noexcept;

// ============================================================================
// Anomaly Detection
// ============================================================================

/**
 * @brief PE anomaly types for malware detection.
 */
enum class AnomalyType : uint32_t {
    None = 0,

    // Header anomalies
    DosStubMissing,
    DosStubModified,
    MultiplePeSignatures,
    UnusualLfanew,
    TimestampInFuture,
    TimestampZero,
    TimestampVeryOld,
    ChecksumMismatch,
    ChecksumZero,
    SubsystemMismatch,

    // Section anomalies
    SectionNameEmpty,
    SectionNameNonPrintable,
    SectionNameSuspicious,
    SectionWritableExecutable,
    SectionZeroRawSize,
    SectionHighEntropy,
    SectionLowEntropy,
    SectionSizeMismatch,
    TooManySections,
    UnusualSectionOrder,
    CodeOutsideCodeSection,

    // Entry point anomalies
    EntryPointInHeader,
    EntryPointInLastSection,
    EntryPointInWritableSection,
    EntryPointNearEnd,
    EntryPointZero,
    EntryPointOutsideFile,

    // Import anomalies
    NoImports,
    SuspiciousImports,
    ApiHashing,
    DelayLoadSuspicious,

    // Export anomalies
    ExportsInExecutable,
    SuspiciousExportNames,
    ForwardedExports,

    // TLS anomalies
    TLSCallbackPresent,
    TLSCallbackInWritable,
    MultipleTLSCallbacks,

    // Resource anomalies
    ResourcesContainPE,
    ResourcesHighEntropy,
    ResourceSizeAnomaly,

    // Packing/Protection indicators
    PackerSignatureDetected,
    OverlayPresent,
    OverlayHighEntropy,
    SelfModifyingCode,

    // .NET anomalies
    DotNetNativeCode,
    DotNetObfuscated,

    // Security anomalies
    NoASLR,
    NoDEP,
    NoSEH,
    NoCFG,
    WeakChecksum,
};

/**
 * @brief Detected anomaly with details.
 */
struct Anomaly {
    AnomalyType type = AnomalyType::None;
    std::wstring description;
    uint64_t offset = 0;
    std::wstring context;

    Anomaly() = default;
    Anomaly(AnomalyType t, const wchar_t* desc)
        : type(t), description(desc ? desc : L"") {}
    Anomaly(AnomalyType t, const wchar_t* desc, uint64_t off, const wchar_t* ctx)
        : type(t), description(desc ? desc : L""), offset(off), context(ctx ? ctx : L"") {}
};

} // namespace PEParser
} // namespace ShadowStrike
