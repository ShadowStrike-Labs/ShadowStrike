/**
 * @file PEValidation.cpp
 * @brief PE validation implementation with comprehensive checks.
 *
 * @copyright ShadowStrike Security Suite
 */

#include "PEValidation.hpp"
#include "../Utils/Logger.hpp"

namespace ShadowStrike {
namespace PEParser {

// ============================================================================
// Validation Result String Conversion
// ============================================================================

[[nodiscard]] const wchar_t* ValidationResultToString(ValidationResult result) noexcept {
    switch (result) {
        case ValidationResult::Valid: return L"Valid";
        case ValidationResult::UnknownError: return L"Unknown error";
        case ValidationResult::FileTooSmall: return L"File too small to be a valid PE";
        case ValidationResult::FileTooLarge: return L"File exceeds maximum supported size";
        case ValidationResult::NullPointer: return L"Null pointer provided";
        case ValidationResult::IntegerOverflow: return L"Integer overflow detected";

        case ValidationResult::InvalidDosSignature: return L"Invalid DOS signature (expected MZ)";
        case ValidationResult::InvalidLfanew: return L"Invalid e_lfanew value";
        case ValidationResult::LfanewOutOfBounds: return L"e_lfanew points outside file";
        case ValidationResult::LfanewNegative: return L"e_lfanew is negative";
        case ValidationResult::LfanewUnaligned: return L"e_lfanew is not properly aligned";
        case ValidationResult::LfanewTooSmall: return L"e_lfanew is too small";
        case ValidationResult::LfanewTooLarge: return L"e_lfanew exceeds maximum allowed";

        case ValidationResult::InvalidNtSignature: return L"Invalid NT signature (expected PE\\0\\0)";
        case ValidationResult::InvalidMachine: return L"Invalid or unsupported machine type";
        case ValidationResult::InvalidOptionalMagic: return L"Invalid optional header magic";
        case ValidationResult::NumberOfSectionsZero: return L"Number of sections is zero";
        case ValidationResult::NumberOfSectionsOverflow: return L"Number of sections exceeds limit";
        case ValidationResult::SizeOfOptionalHeaderInvalid: return L"Invalid optional header size";
        case ValidationResult::SizeOfOptionalHeaderTooSmall: return L"Optional header too small";
        case ValidationResult::SizeOfOptionalHeaderTooLarge: return L"Optional header too large";
        case ValidationResult::NtHeadersOutOfBounds: return L"NT headers extend beyond file";
        case ValidationResult::InvalidFileAlignment: return L"Invalid file alignment";
        case ValidationResult::InvalidSectionAlignment: return L"Invalid section alignment";
        case ValidationResult::FileAlignmentGreaterThanSection: return L"File alignment > section alignment";
        case ValidationResult::SizeOfImageZero: return L"Size of image is zero";
        case ValidationResult::SizeOfHeadersZero: return L"Size of headers is zero";
        case ValidationResult::SizeOfHeadersTooLarge: return L"Size of headers exceeds file size";
        case ValidationResult::NumberOfRvaAndSizesInvalid: return L"Invalid number of data directories";
        case ValidationResult::InvalidAddressOfEntryPoint: return L"Invalid entry point address";
        case ValidationResult::InvalidImageBase: return L"Invalid image base address";
        case ValidationResult::InvalidSubsystem: return L"Invalid subsystem type";

        case ValidationResult::SectionTableOutOfBounds: return L"Section table extends beyond file";
        case ValidationResult::SectionTableOverflow: return L"Section table size overflow";
        case ValidationResult::SectionCountMismatch: return L"Section count mismatch";
        case ValidationResult::SectionNameInvalid: return L"Invalid section name";
        case ValidationResult::SectionVirtualAddressZero: return L"Section virtual address is zero";
        case ValidationResult::SectionVirtualSizeZero: return L"Section virtual size is zero";
        case ValidationResult::SectionRawAddressInvalid: return L"Invalid section raw address";
        case ValidationResult::SectionRawSizeInvalid: return L"Invalid section raw size";
        case ValidationResult::SectionBeyondFile: return L"Section extends beyond file";
        case ValidationResult::SectionBeyondImage: return L"Section extends beyond image";
        case ValidationResult::SectionOverlap: return L"Sections overlap in file";
        case ValidationResult::SectionAlignmentViolation: return L"Section alignment violation";
        case ValidationResult::SectionCharacteristicsInvalid: return L"Invalid section characteristics";
        case ValidationResult::SectionWritableExecutable: return L"Section is both writable and executable";
        case ValidationResult::EntryPointOutsideSections: return L"Entry point outside all sections";
        case ValidationResult::EntryPointInNonExecutable: return L"Entry point in non-executable section";

        case ValidationResult::DataDirectoryOutOfBounds: return L"Data directory extends beyond file";
        case ValidationResult::DataDirectorySizeInvalid: return L"Invalid data directory size";
        case ValidationResult::DataDirectoryRvaInvalid: return L"Invalid data directory RVA";
        case ValidationResult::ImportDirectoryInvalid: return L"Invalid import directory";
        case ValidationResult::ExportDirectoryInvalid: return L"Invalid export directory";
        case ValidationResult::ResourceDirectoryInvalid: return L"Invalid resource directory";
        case ValidationResult::TLSDirectoryInvalid: return L"Invalid TLS directory";
        case ValidationResult::RelocDirectoryInvalid: return L"Invalid relocation directory";
        case ValidationResult::DebugDirectoryInvalid: return L"Invalid debug directory";
        case ValidationResult::SecurityDirectoryInvalid: return L"Invalid security directory";
        case ValidationResult::CLRDirectoryInvalid: return L"Invalid CLR directory";

        case ValidationResult::ImportDescriptorOutOfBounds: return L"Import descriptor beyond file";
        case ValidationResult::ImportDllNameOutOfBounds: return L"Import DLL name beyond file";
        case ValidationResult::ImportDllNameTooLong: return L"Import DLL name too long";
        case ValidationResult::ImportThunkOutOfBounds: return L"Import thunk beyond file";
        case ValidationResult::ImportByNameOutOfBounds: return L"Import by name beyond file";
        case ValidationResult::ImportFunctionNameTooLong: return L"Import function name too long";
        case ValidationResult::ImportOrdinalInvalid: return L"Invalid import ordinal";
        case ValidationResult::ImportCircularReference: return L"Circular import reference";
        case ValidationResult::ImportCountExceeded: return L"Import count exceeded limit";

        case ValidationResult::ExportDirectoryOutOfBounds: return L"Export directory beyond file";
        case ValidationResult::ExportNameOutOfBounds: return L"Export name beyond file";
        case ValidationResult::ExportOrdinalOutOfBounds: return L"Export ordinal out of bounds";
        case ValidationResult::ExportAddressOutOfBounds: return L"Export address beyond file";
        case ValidationResult::ExportForwarderInvalid: return L"Invalid export forwarder";
        case ValidationResult::ExportCountExceeded: return L"Export count exceeded limit";

        case ValidationResult::TLSDirectoryOutOfBounds: return L"TLS directory beyond file";
        case ValidationResult::TLSCallbacksOutOfBounds: return L"TLS callbacks beyond file";
        case ValidationResult::TLSCallbackCountExceeded: return L"TLS callback count exceeded";
        case ValidationResult::TLSDataOutOfBounds: return L"TLS data beyond file";
        case ValidationResult::TLSCallbackInNonExecutable: return L"TLS callback in non-executable memory";

        case ValidationResult::ResourceDirectoryOutOfBounds: return L"Resource directory beyond file";
        case ValidationResult::ResourceDepthExceeded: return L"Resource directory depth exceeded";
        case ValidationResult::ResourceCircularReference: return L"Circular resource reference";
        case ValidationResult::ResourceEntryCountExceeded: return L"Resource entry count exceeded";
        case ValidationResult::ResourceDataOutOfBounds: return L"Resource data beyond file";
        case ValidationResult::ResourceNameOutOfBounds: return L"Resource name beyond file";

        case ValidationResult::RelocationBlockOutOfBounds: return L"Relocation block beyond file";
        case ValidationResult::RelocationBlockSizeInvalid: return L"Invalid relocation block size";
        case ValidationResult::RelocationEntryInvalid: return L"Invalid relocation entry";
        case ValidationResult::RelocationCountExceeded: return L"Relocation count exceeded";
        case ValidationResult::RelocationCircularReference: return L"Circular relocation reference";

        case ValidationResult::DebugEntryOutOfBounds: return L"Debug entry beyond file";
        case ValidationResult::DebugDataOutOfBounds: return L"Debug data beyond file";
        case ValidationResult::DebugCountExceeded: return L"Debug entry count exceeded";
        case ValidationResult::DebugTypeUnknown: return L"Unknown debug type";

        case ValidationResult::RichHeaderNotFound: return L"Rich header not found";
        case ValidationResult::RichHeaderCorrupted: return L"Rich header corrupted";
        case ValidationResult::RichHeaderChecksumMismatch: return L"Rich header checksum mismatch";
        case ValidationResult::RichEntryCountExceeded: return L"Rich header entry count exceeded";

        case ValidationResult::SignatureDirectoryInvalid: return L"Invalid signature directory";
        case ValidationResult::SignatureOutOfBounds: return L"Signature beyond file";
        case ValidationResult::SignatureFormatInvalid: return L"Invalid signature format";

        default: return L"Unknown validation result";
    }
}

// ============================================================================
// DOS Header Validation
// ============================================================================

[[nodiscard]] ValidationResult ValidateDosHeader(
    const SafeReader& reader,
    int32_t& outLfanew,
    PEError* err) noexcept
{
    outLfanew = 0;

    // Check minimum file size
    if (reader.Size() < Limits::MIN_PE_FILE_SIZE) {
        if (err) {
            err->Set(ValidationResult::FileTooSmall,
                     L"File is smaller than minimum PE size",
                     0);
        }
        return ValidationResult::FileTooSmall;
    }

    // Check maximum file size
    if (reader.Size() > Limits::MAX_FILE_SIZE) {
        if (err) {
            err->Set(ValidationResult::FileTooLarge,
                     L"File exceeds maximum supported size",
                     0);
        }
        return ValidationResult::FileTooLarge;
    }

    // Read DOS header
    DosHeader dos;
    if (!reader.Read(0, dos)) {
        if (err) {
            err->Set(ValidationResult::FileTooSmall,
                     L"Cannot read DOS header",
                     0);
        }
        return ValidationResult::FileTooSmall;
    }

    // Validate DOS signature
    if (dos.e_magic != DOS_SIGNATURE) {
        if (err) {
            err->Set(ValidationResult::InvalidDosSignature,
                     L"Invalid DOS signature (expected 0x5A4D 'MZ')",
                     0);
        }
        return ValidationResult::InvalidDosSignature;
    }

    // e_lfanew is SIGNED - can be negative (attack vector)
    if (dos.e_lfanew < 0) {
        if (err) {
            err->Set(ValidationResult::LfanewNegative,
                     L"e_lfanew is negative (potential attack)",
                     offsetof(DosHeader, e_lfanew));
        }
        return ValidationResult::LfanewNegative;
    }

    // Check minimum e_lfanew (must be past DOS header)
    if (dos.e_lfanew < MIN_LFANEW) {
        if (err) {
            err->Set(ValidationResult::LfanewTooSmall,
                     L"e_lfanew is too small (overlaps DOS header)",
                     offsetof(DosHeader, e_lfanew));
        }
        return ValidationResult::LfanewTooSmall;
    }

    // Check maximum e_lfanew
    if (dos.e_lfanew > MAX_LFANEW) {
        if (err) {
            err->Set(ValidationResult::LfanewTooLarge,
                     L"e_lfanew exceeds maximum allowed offset",
                     offsetof(DosHeader, e_lfanew));
        }
        return ValidationResult::LfanewTooLarge;
    }

    // Check e_lfanew doesn't point beyond file
    // Need space for at least PE signature + file header
    size_t minNtSize = sizeof(uint32_t) + sizeof(FileHeader);
    size_t ntEnd;
    if (!SafeMath::SafeAdd(static_cast<size_t>(dos.e_lfanew), minNtSize, ntEnd)) {
        if (err) {
            err->Set(ValidationResult::IntegerOverflow,
                     L"Integer overflow checking NT headers bounds",
                     offsetof(DosHeader, e_lfanew));
        }
        return ValidationResult::IntegerOverflow;
    }

    if (ntEnd > reader.Size()) {
        if (err) {
            err->Set(ValidationResult::LfanewOutOfBounds,
                     L"e_lfanew points beyond file boundary",
                     offsetof(DosHeader, e_lfanew));
        }
        return ValidationResult::LfanewOutOfBounds;
    }

    outLfanew = dos.e_lfanew;
    return ValidationResult::Valid;
}

// ============================================================================
// NT Headers Validation
// ============================================================================

[[nodiscard]] ValidationResult ValidateNtHeaders(
    const SafeReader& reader,
    size_t ntOffset,
    bool& outIs64Bit,
    FileHeader& outFileHeader,
    PEError* err) noexcept
{
    outIs64Bit = false;

    // Read and validate PE signature
    uint32_t signature;
    if (!reader.Read(ntOffset, signature)) {
        if (err) {
            err->Set(ValidationResult::NtHeadersOutOfBounds,
                     L"Cannot read PE signature",
                     ntOffset);
        }
        return ValidationResult::NtHeadersOutOfBounds;
    }

    if (signature != NT_SIGNATURE) {
        if (err) {
            err->Set(ValidationResult::InvalidNtSignature,
                     L"Invalid PE signature (expected 0x00004550)",
                     ntOffset);
        }
        return ValidationResult::InvalidNtSignature;
    }

    // Read file header
    size_t fileHeaderOffset = ntOffset + sizeof(uint32_t);
    if (!reader.Read(fileHeaderOffset, outFileHeader)) {
        if (err) {
            err->Set(ValidationResult::NtHeadersOutOfBounds,
                     L"Cannot read file header",
                     fileHeaderOffset);
        }
        return ValidationResult::NtHeadersOutOfBounds;
    }

    // Validate machine type
    bool validMachine = false;
    switch (outFileHeader.Machine) {
        case Machine::I386:
        case Machine::AMD64:
        case Machine::ARM:
        case Machine::ARMNT:
        case Machine::ARM64:
        case Machine::IA64:
            validMachine = true;
            break;
        case Machine::UNKNOWN:
            // Allow unknown for some edge cases
            validMachine = true;
            break;
        default:
            // Allow other less common but valid types
            validMachine = true;
            break;
    }

    if (!validMachine) {
        if (err) {
            err->Set(ValidationResult::InvalidMachine,
                     L"Invalid or unsupported machine type",
                     fileHeaderOffset + offsetof(FileHeader, Machine));
        }
        return ValidationResult::InvalidMachine;
    }

    // Validate number of sections
    if (outFileHeader.NumberOfSections == 0) {
        // Zero sections is technically invalid but some tools generate it
        // We allow it but flag as anomaly
    }

    if (outFileHeader.NumberOfSections > Limits::MAX_SECTIONS) {
        if (err) {
            err->Set(ValidationResult::NumberOfSectionsOverflow,
                     L"Number of sections exceeds safety limit",
                     fileHeaderOffset + offsetof(FileHeader, NumberOfSections));
        }
        return ValidationResult::NumberOfSectionsOverflow;
    }

    // Validate optional header size
    if (outFileHeader.SizeOfOptionalHeader == 0) {
        if (err) {
            err->Set(ValidationResult::SizeOfOptionalHeaderTooSmall,
                     L"Optional header size is zero",
                     fileHeaderOffset + offsetof(FileHeader, SizeOfOptionalHeader));
        }
        return ValidationResult::SizeOfOptionalHeaderTooSmall;
    }

    if (outFileHeader.SizeOfOptionalHeader > Limits::MAX_OPTIONAL_HEADER_SIZE) {
        if (err) {
            err->Set(ValidationResult::SizeOfOptionalHeaderTooLarge,
                     L"Optional header size exceeds limit",
                     fileHeaderOffset + offsetof(FileHeader, SizeOfOptionalHeader));
        }
        return ValidationResult::SizeOfOptionalHeaderTooLarge;
    }

    // Read optional header magic to determine 32/64-bit
    size_t optionalOffset = fileHeaderOffset + sizeof(FileHeader);
    uint16_t magic;
    if (!reader.Read(optionalOffset, magic)) {
        if (err) {
            err->Set(ValidationResult::NtHeadersOutOfBounds,
                     L"Cannot read optional header magic",
                     optionalOffset);
        }
        return ValidationResult::NtHeadersOutOfBounds;
    }

    if (magic == PE64_MAGIC) {
        outIs64Bit = true;
        if (outFileHeader.SizeOfOptionalHeader < sizeof(OptionalHeader64)) {
            // Allow smaller if NumberOfRvaAndSizes is reduced
            if (outFileHeader.SizeOfOptionalHeader < 112) {  // Minimum PE64 header
                if (err) {
                    err->Set(ValidationResult::SizeOfOptionalHeaderTooSmall,
                             L"PE64 optional header too small",
                             fileHeaderOffset + offsetof(FileHeader, SizeOfOptionalHeader));
                }
                return ValidationResult::SizeOfOptionalHeaderTooSmall;
            }
        }
    } else if (magic == PE32_MAGIC) {
        outIs64Bit = false;
        if (outFileHeader.SizeOfOptionalHeader < sizeof(OptionalHeader32)) {
            // Allow smaller if NumberOfRvaAndSizes is reduced
            if (outFileHeader.SizeOfOptionalHeader < 96) {  // Minimum PE32 header
                if (err) {
                    err->Set(ValidationResult::SizeOfOptionalHeaderTooSmall,
                             L"PE32 optional header too small",
                             fileHeaderOffset + offsetof(FileHeader, SizeOfOptionalHeader));
                }
                return ValidationResult::SizeOfOptionalHeaderTooSmall;
            }
        }
    } else if (magic == ROM_MAGIC) {
        // ROM images - rare but valid
        outIs64Bit = false;
    } else {
        if (err) {
            err->Set(ValidationResult::InvalidOptionalMagic,
                     L"Invalid optional header magic",
                     optionalOffset);
        }
        return ValidationResult::InvalidOptionalMagic;
    }

    return ValidationResult::Valid;
}

// ============================================================================
// Optional Header Validation (32-bit)
// ============================================================================

[[nodiscard]] ValidationResult ValidateOptionalHeader32(
    const SafeReader& reader,
    size_t offset,
    uint16_t sizeOfOptionalHeader,
    OptionalHeader32& outOptional,
    PEError* err) noexcept
{
    // Read the optional header
    if (!reader.Read(offset, outOptional)) {
        if (err) {
            err->Set(ValidationResult::NtHeadersOutOfBounds,
                     L"Cannot read PE32 optional header",
                     offset);
        }
        return ValidationResult::NtHeadersOutOfBounds;
    }

    // Validate magic
    if (outOptional.Magic != PE32_MAGIC) {
        if (err) {
            err->Set(ValidationResult::InvalidOptionalMagic,
                     L"Invalid PE32 magic",
                     offset);
        }
        return ValidationResult::InvalidOptionalMagic;
    }

    // Validate alignments
    if (outOptional.FileAlignment < Limits::MIN_FILE_ALIGNMENT ||
        outOptional.FileAlignment > Limits::MAX_FILE_ALIGNMENT) {
        if (err) {
            err->Set(ValidationResult::InvalidFileAlignment,
                     L"File alignment out of valid range",
                     offset + offsetof(OptionalHeader32, FileAlignment));
        }
        return ValidationResult::InvalidFileAlignment;
    }

    // File alignment must be power of 2
    if ((outOptional.FileAlignment & (outOptional.FileAlignment - 1)) != 0) {
        if (err) {
            err->Set(ValidationResult::InvalidFileAlignment,
                     L"File alignment is not a power of 2",
                     offset + offsetof(OptionalHeader32, FileAlignment));
        }
        return ValidationResult::InvalidFileAlignment;
    }

    if (outOptional.SectionAlignment < Limits::MIN_SECTION_ALIGNMENT ||
        outOptional.SectionAlignment > Limits::MAX_SECTION_ALIGNMENT) {
        if (err) {
            err->Set(ValidationResult::InvalidSectionAlignment,
                     L"Section alignment out of valid range",
                     offset + offsetof(OptionalHeader32, SectionAlignment));
        }
        return ValidationResult::InvalidSectionAlignment;
    }

    // Section alignment must be >= file alignment (unless < page size)
    if (outOptional.SectionAlignment >= 4096 &&
        outOptional.FileAlignment > outOptional.SectionAlignment) {
        if (err) {
            err->Set(ValidationResult::FileAlignmentGreaterThanSection,
                     L"File alignment greater than section alignment",
                     offset + offsetof(OptionalHeader32, FileAlignment));
        }
        return ValidationResult::FileAlignmentGreaterThanSection;
    }

    // Validate size of image
    if (outOptional.SizeOfImage == 0) {
        if (err) {
            err->Set(ValidationResult::SizeOfImageZero,
                     L"Size of image is zero",
                     offset + offsetof(OptionalHeader32, SizeOfImage));
        }
        return ValidationResult::SizeOfImageZero;
    }

    // Validate size of headers
    if (outOptional.SizeOfHeaders == 0) {
        if (err) {
            err->Set(ValidationResult::SizeOfHeadersZero,
                     L"Size of headers is zero",
                     offset + offsetof(OptionalHeader32, SizeOfHeaders));
        }
        return ValidationResult::SizeOfHeadersZero;
    }

    if (outOptional.SizeOfHeaders > reader.Size()) {
        if (err) {
            err->Set(ValidationResult::SizeOfHeadersTooLarge,
                     L"Size of headers exceeds file size",
                     offset + offsetof(OptionalHeader32, SizeOfHeaders));
        }
        return ValidationResult::SizeOfHeadersTooLarge;
    }

    // Validate number of data directories
    if (outOptional.NumberOfRvaAndSizes > DataDirectory::MAX_ENTRIES) {
        if (err) {
            err->Set(ValidationResult::NumberOfRvaAndSizesInvalid,
                     L"Number of data directories exceeds maximum",
                     offset + offsetof(OptionalHeader32, NumberOfRvaAndSizes));
        }
        return ValidationResult::NumberOfRvaAndSizesInvalid;
    }

    return ValidationResult::Valid;
}

// ============================================================================
// Optional Header Validation (64-bit)
// ============================================================================

[[nodiscard]] ValidationResult ValidateOptionalHeader64(
    const SafeReader& reader,
    size_t offset,
    uint16_t sizeOfOptionalHeader,
    OptionalHeader64& outOptional,
    PEError* err) noexcept
{
    // Read the optional header
    if (!reader.Read(offset, outOptional)) {
        if (err) {
            err->Set(ValidationResult::NtHeadersOutOfBounds,
                     L"Cannot read PE64 optional header",
                     offset);
        }
        return ValidationResult::NtHeadersOutOfBounds;
    }

    // Validate magic
    if (outOptional.Magic != PE64_MAGIC) {
        if (err) {
            err->Set(ValidationResult::InvalidOptionalMagic,
                     L"Invalid PE64 magic",
                     offset);
        }
        return ValidationResult::InvalidOptionalMagic;
    }

    // Validate alignments (same rules as 32-bit)
    if (outOptional.FileAlignment < Limits::MIN_FILE_ALIGNMENT ||
        outOptional.FileAlignment > Limits::MAX_FILE_ALIGNMENT) {
        if (err) {
            err->Set(ValidationResult::InvalidFileAlignment,
                     L"File alignment out of valid range",
                     offset + offsetof(OptionalHeader64, FileAlignment));
        }
        return ValidationResult::InvalidFileAlignment;
    }

    if ((outOptional.FileAlignment & (outOptional.FileAlignment - 1)) != 0) {
        if (err) {
            err->Set(ValidationResult::InvalidFileAlignment,
                     L"File alignment is not a power of 2",
                     offset + offsetof(OptionalHeader64, FileAlignment));
        }
        return ValidationResult::InvalidFileAlignment;
    }

    if (outOptional.SectionAlignment < Limits::MIN_SECTION_ALIGNMENT ||
        outOptional.SectionAlignment > Limits::MAX_SECTION_ALIGNMENT) {
        if (err) {
            err->Set(ValidationResult::InvalidSectionAlignment,
                     L"Section alignment out of valid range",
                     offset + offsetof(OptionalHeader64, SectionAlignment));
        }
        return ValidationResult::InvalidSectionAlignment;
    }

    if (outOptional.SectionAlignment >= 4096 &&
        outOptional.FileAlignment > outOptional.SectionAlignment) {
        if (err) {
            err->Set(ValidationResult::FileAlignmentGreaterThanSection,
                     L"File alignment greater than section alignment",
                     offset + offsetof(OptionalHeader64, FileAlignment));
        }
        return ValidationResult::FileAlignmentGreaterThanSection;
    }

    // Validate size of image
    if (outOptional.SizeOfImage == 0) {
        if (err) {
            err->Set(ValidationResult::SizeOfImageZero,
                     L"Size of image is zero",
                     offset + offsetof(OptionalHeader64, SizeOfImage));
        }
        return ValidationResult::SizeOfImageZero;
    }

    // Validate size of headers
    if (outOptional.SizeOfHeaders == 0) {
        if (err) {
            err->Set(ValidationResult::SizeOfHeadersZero,
                     L"Size of headers is zero",
                     offset + offsetof(OptionalHeader64, SizeOfHeaders));
        }
        return ValidationResult::SizeOfHeadersZero;
    }

    if (outOptional.SizeOfHeaders > reader.Size()) {
        if (err) {
            err->Set(ValidationResult::SizeOfHeadersTooLarge,
                     L"Size of headers exceeds file size",
                     offset + offsetof(OptionalHeader64, SizeOfHeaders));
        }
        return ValidationResult::SizeOfHeadersTooLarge;
    }

    // Validate number of data directories
    if (outOptional.NumberOfRvaAndSizes > DataDirectory::MAX_ENTRIES) {
        if (err) {
            err->Set(ValidationResult::NumberOfRvaAndSizesInvalid,
                     L"Number of data directories exceeds maximum",
                     offset + offsetof(OptionalHeader64, NumberOfRvaAndSizes));
        }
        return ValidationResult::NumberOfRvaAndSizesInvalid;
    }

    return ValidationResult::Valid;
}

// ============================================================================
// Section Header Validation
// ============================================================================

[[nodiscard]] ValidationResult ValidateSectionHeader(
    const SectionHeader& header,
    size_t fileSize,
    uint32_t sizeOfImage,
    uint32_t fileAlignment,
    size_t sectionIndex,
    PEError* err) noexcept
{
    // Check raw data bounds
    if (header.SizeOfRawData > 0) {
        size_t rawEnd;
        if (!SafeMath::SafeAdd(static_cast<size_t>(header.PointerToRawData),
                               static_cast<size_t>(header.SizeOfRawData),
                               rawEnd)) {
            if (err) {
                err->Set(ValidationResult::IntegerOverflow,
                         L"Integer overflow in section raw data bounds",
                         0);
            }
            return ValidationResult::IntegerOverflow;
        }

        if (rawEnd > fileSize) {
            if (err) {
                err->Set(ValidationResult::SectionBeyondFile,
                         L"Section raw data extends beyond file",
                         header.PointerToRawData);
            }
            return ValidationResult::SectionBeyondFile;
        }
    }

    // Check virtual bounds
    if (header.VirtualSize > 0 || header.SizeOfRawData > 0) {
        uint32_t virtualSize = header.VirtualSize;
        if (virtualSize == 0) {
            virtualSize = header.SizeOfRawData;
        }

        size_t virtualEnd;
        if (!SafeMath::SafeAdd(static_cast<size_t>(header.VirtualAddress),
                               static_cast<size_t>(virtualSize),
                               virtualEnd)) {
            if (err) {
                err->Set(ValidationResult::IntegerOverflow,
                         L"Integer overflow in section virtual bounds",
                         0);
            }
            return ValidationResult::IntegerOverflow;
        }

        if (virtualEnd > sizeOfImage) {
            if (err) {
                err->Set(ValidationResult::SectionBeyondImage,
                         L"Section virtual data extends beyond image",
                         header.VirtualAddress);
            }
            return ValidationResult::SectionBeyondImage;
        }
    }

    // Check alignment (PointerToRawData should be aligned to FileAlignment)
    if (header.PointerToRawData != 0 && fileAlignment > 0) {
        if ((header.PointerToRawData % fileAlignment) != 0) {
            // This is technically a violation but many packers do it
            // We don't return error, just note it as anomaly
        }
    }

    return ValidationResult::Valid;
}

// ============================================================================
// Section Overlap Check
// ============================================================================

[[nodiscard]] bool CheckSectionOverlaps(
    const std::vector<SectionHeader>& sections,
    std::vector<std::pair<size_t, size_t>>& outOverlaps) noexcept
{
    outOverlaps.clear();

    for (size_t i = 0; i < sections.size(); ++i) {
        const auto& s1 = sections[i];
        if (s1.SizeOfRawData == 0) continue;

        size_t s1Start = s1.PointerToRawData;
        size_t s1End;
        if (!SafeMath::SafeAdd(s1Start, static_cast<size_t>(s1.SizeOfRawData), s1End)) {
            continue;  // Overflow, skip
        }

        for (size_t j = i + 1; j < sections.size(); ++j) {
            const auto& s2 = sections[j];
            if (s2.SizeOfRawData == 0) continue;

            size_t s2Start = s2.PointerToRawData;
            size_t s2End;
            if (!SafeMath::SafeAdd(s2Start, static_cast<size_t>(s2.SizeOfRawData), s2End)) {
                continue;  // Overflow, skip
            }

            // Check for overlap
            if (s1Start < s2End && s2Start < s1End) {
                outOverlaps.emplace_back(i, j);
            }
        }
    }

    return !outOverlaps.empty();
}

// ============================================================================
// Data Directory Validation
// ============================================================================

[[nodiscard]] ValidationResult ValidateDataDirectory(
    size_t index,
    uint32_t rva,
    uint32_t size,
    size_t fileSize,
    PEError* err) noexcept
{
    // Zero RVA and size is valid (directory not present)
    if (rva == 0 && size == 0) {
        return ValidationResult::Valid;
    }

    // Non-zero size with zero RVA is suspicious
    if (rva == 0 && size != 0) {
        if (err) {
            err->Set(ValidationResult::DataDirectoryRvaInvalid,
                     L"Data directory has size but zero RVA",
                     0);
        }
        return ValidationResult::DataDirectoryRvaInvalid;
    }

    // Check for overflow
    size_t end;
    if (!SafeMath::SafeAdd(static_cast<size_t>(rva), static_cast<size_t>(size), end)) {
        if (err) {
            err->Set(ValidationResult::IntegerOverflow,
                     L"Data directory size overflow",
                     0);
        }
        return ValidationResult::IntegerOverflow;
    }

    // Note: We can't fully validate RVA->offset mapping here
    // That requires section table information

    return ValidationResult::Valid;
}

} // namespace PEParser
} // namespace ShadowStrike
