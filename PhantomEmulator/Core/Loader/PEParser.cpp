/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * PEParser.cpp — PE32/PE64 parser implementation
 *
 * Production-grade, hostile-input-safe parser for Portable Executable files.
 * Every offset, size, count, and RVA is validated before use. Designed to
 * survive nation-state APT samples, packer mutations, and fuzzer output
 * without crashing, hanging, or leaking information.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "PEParser.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace Phantom {

// ============================================================================
// Internal helpers (file-local)
// ============================================================================

namespace {

/// Safely read a trivially-copyable value from a byte span at a given offset.
/// Returns false if the read would exceed bounds.
template <typename T>
[[nodiscard]] bool SafeRead(ByteSpan data, uint32_t offset, T& out) noexcept {
    static_assert(std::is_trivially_copyable_v<T>);
    if (offset > data.size() || (data.size() - offset) < sizeof(T)) {
        return false;
    }
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

/// Check that a value is a power of two (and non-zero).
[[nodiscard]] constexpr bool IsPowerOfTwo(uint32_t v) noexcept {
    return v != 0 && (v & (v - 1)) == 0;
}

/// Convert PE section characteristics to MemProt.
[[nodiscard]] constexpr MemProt CharacteristicsToMemProt(uint32_t ch) noexcept {
    MemProt prot = MemProt::None;
    if (ch & PE::kSecMemRead)    prot = prot | MemProt::Read;
    if (ch & PE::kSecMemWrite)   prot = prot | MemProt::Write;
    if (ch & PE::kSecMemExecute) prot = prot | MemProt::Execute;
    // Default: readable if nothing else specified
    if (prot == MemProt::None) prot = MemProt::Read;
    return prot;
}

/// Cap on e_lfanew to prevent degenerate files from causing huge offsets.
static constexpr uint32_t kMaxElfanew = 1024 * 1024; // 1 MB

/// Maximum SizeOfImage we accept (512 MB).
static constexpr uint32_t kMaxSizeOfImage = 512 * 1024 * 1024;

/// Maximum number of relocation entries across all blocks (prevents DoS).
static constexpr uint32_t kMaxTotalRelocEntries = 2 * 1024 * 1024;

/// Sentinel: a fully-zeroed ImportDescriptor marks end of import table.
[[nodiscard]] bool IsNullImportDescriptor(const PE::ImportDescriptor& id) noexcept {
    return id.OriginalFirstThunk == 0 &&
           id.TimeDateStamp     == 0 &&
           id.ForwarderChain    == 0 &&
           id.Name              == 0 &&
           id.FirstThunk        == 0;
}

} // anonymous namespace

// ============================================================================
// PEParser::IsPE
// ============================================================================

bool PEParser::IsPE(ByteSpan data) noexcept {
    if (data.size() < sizeof(PE::DOSHeader)) {
        return false;
    }

    PE::DOSHeader dos{};
    if (!SafeRead(data, 0, dos)) return false;
    if (dos.e_magic != PE::kDOSMagic) return false;

    const auto lfanew = static_cast<uint32_t>(dos.e_lfanew);
    if (lfanew < sizeof(PE::DOSHeader)) return false;
    if (lfanew >= data.size()) return false;

    // Read PE signature (4 bytes)
    uint32_t sig = 0;
    if (!SafeRead(data, lfanew, sig)) return false;
    return sig == PE::kNTSignature;
}

// ============================================================================
// PEParser::Is64Bit
// ============================================================================

std::optional<bool> PEParser::Is64Bit(ByteSpan data) noexcept {
    if (data.size() < sizeof(PE::DOSHeader)) return std::nullopt;

    PE::DOSHeader dos{};
    if (!SafeRead(data, 0, dos)) return std::nullopt;
    if (dos.e_magic != PE::kDOSMagic) return std::nullopt;

    const auto lfanew = static_cast<uint32_t>(dos.e_lfanew);
    if (lfanew < sizeof(PE::DOSHeader) || lfanew >= data.size()) return std::nullopt;

    uint32_t sig = 0;
    if (!SafeRead(data, lfanew, sig)) return std::nullopt;
    if (sig != PE::kNTSignature) return std::nullopt;

    // Optional header magic sits right after Signature + FileHeader
    const uint32_t optMagicOffset = lfanew + sizeof(uint32_t) + sizeof(PE::FileHeader);
    uint16_t magic = 0;
    if (!SafeRead(data, optMagicOffset, magic)) return std::nullopt;

    if (magic == PE::kPE64Magic) return true;
    if (magic == PE::kPE32Magic) return false;
    return std::nullopt;
}

// ============================================================================
// PEParser::RVAToFileOffset
// ============================================================================

std::optional<uint32_t> PEParser::RVAToFileOffset(
    const ParsedPE& pe, uint32_t rva) noexcept
{
    // RVAs within the headers map 1:1 to file offsets
    if (rva < pe.sizeOfHeaders) {
        return rva;
    }

    for (const auto& sec : pe.sections) {
        // Compute the effective virtual size.
        // Some sections have VirtualSize == 0 (anti-evasion edge case);
        // in that case fall back to SizeOfRawData.
        uint32_t effectiveVSize = sec.virtualSize;
        if (effectiveVSize == 0) {
            effectiveVSize = sec.rawDataSize;
        }

        if (rva >= sec.virtualAddress && (rva - sec.virtualAddress) < effectiveVSize) {
            const uint32_t delta = rva - sec.virtualAddress;
            // If the offset falls beyond raw data, it's in the zero-fill
            // region (BSS) — there is no file backing.
            if (delta >= sec.rawDataSize) {
                return std::nullopt;
            }
            // Overflow-safe: rawDataOffset + delta. Both are uint32_t and
            // we already verified delta < rawDataSize.
            const uint64_t fileOff = static_cast<uint64_t>(sec.rawDataOffset) + delta;
            if (fileOff > 0xFFFFFFFFULL || static_cast<uint32_t>(fileOff) >= pe.rawData.size()) {
                return std::nullopt;
            }
            return static_cast<uint32_t>(fileOff);
        }
    }
    return std::nullopt;
}

// ============================================================================
// PEParser::ReadString
// ============================================================================

std::string PEParser::ReadString(
    ByteSpan data, uint32_t fileOffset, uint32_t maxLen) noexcept
{
    if (fileOffset >= data.size()) return {};

    const uint32_t avail = static_cast<uint32_t>(data.size() - fileOffset);
    const uint32_t limit = (avail < maxLen) ? avail : maxLen;
    const auto* ptr = reinterpret_cast<const char*>(data.data() + fileOffset);

    // Find the null terminator within the capped range
    const auto* end = static_cast<const char*>(std::memchr(ptr, '\0', limit));
    const uint32_t len = end ? static_cast<uint32_t>(end - ptr) : limit;

    // Validate that every byte is a printable ASCII character or common symbol.
    // Import/export names are strictly ASCII. Reject if any byte is < 0x20
    // (except NUL which we already handled) or >= 0x7F.
    for (uint32_t i = 0; i < len; ++i) {
        const auto ch = static_cast<uint8_t>(ptr[i]);
        if (ch < 0x20 || ch >= 0x7F) {
            // Truncate at the first non-printable byte to avoid ingesting garbage.
            return std::string(ptr, i);
        }
    }

    return std::string(ptr, len);
}

// ============================================================================
// PEParser::ValidateDOSHeader
// ============================================================================

ErrorCode PEParser::ValidateDOSHeader(ByteSpan data) noexcept {
    if (data.size() < sizeof(PE::DOSHeader)) {
        return ErrorCode::InvalidPESignature;
    }

    PE::DOSHeader dos{};
    if (!SafeRead(data, 0, dos)) {
        return ErrorCode::InvalidPESignature;
    }

    if (dos.e_magic != PE::kDOSMagic) {
        return ErrorCode::InvalidPESignature;
    }

    const auto lfanew = static_cast<uint32_t>(dos.e_lfanew);

    // e_lfanew must point past the DOS header
    if (lfanew < sizeof(PE::DOSHeader)) {
        return ErrorCode::InvalidPEHeader;
    }

    // e_lfanew must not exceed our cap and must fit in the file
    if (lfanew > kMaxElfanew) {
        return ErrorCode::MalformedPE;
    }

    if (lfanew >= data.size()) {
        return ErrorCode::InvalidPEHeader;
    }

    // There must be room for at least the PE signature after e_lfanew
    if ((data.size() - lfanew) < sizeof(uint32_t)) {
        return ErrorCode::InvalidPEHeader;
    }

    return ErrorCode::Success;
}

// ============================================================================
// PEParser::ValidateNTHeaders
// ============================================================================

ErrorCode PEParser::ValidateNTHeaders(ByteSpan data, int32_t peOffset) noexcept {
    const auto offset = static_cast<uint32_t>(peOffset);

    // Read and verify PE signature
    uint32_t sig = 0;
    if (!SafeRead(data, offset, sig)) {
        return ErrorCode::InvalidPESignature;
    }
    if (sig != PE::kNTSignature) {
        return ErrorCode::InvalidPESignature;
    }

    // Verify room for FileHeader
    const uint32_t fileHdrOffset = offset + sizeof(uint32_t);
    PE::FileHeader fileHdr{};
    if (!SafeRead(data, fileHdrOffset, fileHdr)) {
        return ErrorCode::InvalidPEHeader;
    }

    // Machine type must be one we support (x86 or x64)
    if (fileHdr.Machine != PE::kMachineI386 && fileHdr.Machine != PE::kMachineAMD64) {
        return ErrorCode::UnsupportedMachine;
    }

    // Section count cap
    if (fileHdr.NumberOfSections > PE::kMaxSections) {
        return ErrorCode::SectionOverflow;
    }

    // SizeOfOptionalHeader must be large enough for the magic field at minimum
    if (fileHdr.SizeOfOptionalHeader < sizeof(uint16_t)) {
        return ErrorCode::InvalidPEHeader;
    }

    // Verify room for the optional header
    const uint32_t optHdrOffset = fileHdrOffset + sizeof(PE::FileHeader);
    if (optHdrOffset > data.size() ||
        (data.size() - optHdrOffset) < fileHdr.SizeOfOptionalHeader) {
        return ErrorCode::InvalidPEHeader;
    }

    // Read optional header magic
    uint16_t magic = 0;
    if (!SafeRead(data, optHdrOffset, magic)) {
        return ErrorCode::InvalidPEHeader;
    }

    if (magic == PE::kPE32Magic) {
        // PE32: SizeOfOptionalHeader must be at least the fixed part (without
        // data directories) — 96 bytes. We don't require the full 224 because
        // NumberOfRvaAndSizes may be less than 16.
        if (fileHdr.SizeOfOptionalHeader < 96) {
            return ErrorCode::InvalidPEHeader;
        }
    } else if (magic == PE::kPE64Magic) {
        // PE64: fixed part is 112 bytes
        if (fileHdr.SizeOfOptionalHeader < 112) {
            return ErrorCode::InvalidPEHeader;
        }
    } else {
        return ErrorCode::InvalidPEHeader;
    }

    return ErrorCode::Success;
}

// ============================================================================
// PEParser::ParseSections
// ============================================================================

ErrorCode PEParser::ParseSections(
    ByteSpan data, ParsedPE& pe, uint32_t sectionTableOffset,
    uint16_t sectionCount) noexcept
{
    const auto fileSize = static_cast<uint32_t>(data.size());

    // Verify room for entire section table
    const uint64_t tableEnd =
        static_cast<uint64_t>(sectionTableOffset) +
        static_cast<uint64_t>(sectionCount) * sizeof(PE::SectionHeader);
    if (tableEnd > fileSize) {
        return ErrorCode::InvalidPEHeader;
    }

    // Read each section header
    for (uint32_t i = 0; i < sectionCount; ++i) {
        const uint32_t off = sectionTableOffset + i * sizeof(PE::SectionHeader);

        PE::SectionHeader sh{};
        if (!SafeRead(data, off, sh)) {
            return ErrorCode::InvalidPEHeader;
        }

        ParsedSection sec{};

        // Copy name: up to 8 bytes, forcibly null-terminate
        std::memcpy(sec.name, sh.Name, PE::kMaxSectionNameLen);
        sec.name[PE::kMaxSectionNameLen] = '\0';

        sec.virtualAddress  = sh.VirtualAddress;
        sec.rawDataOffset   = sh.PointerToRawData;
        sec.rawDataSize     = sh.SizeOfRawData;
        sec.characteristics = sh.Characteristics;
        sec.protection      = CharacteristicsToMemProt(sh.Characteristics);

        // ------------------------------------------------------------------
        // Virtual size edge case: some packers set VirtualSize to 0; in that
        // case fall back to SizeOfRawData for mapping purposes.
        // ------------------------------------------------------------------
        sec.virtualSize = (sh.VirtualSize != 0) ? sh.VirtualSize : sh.SizeOfRawData;

        // ------------------------------------------------------------------
        // Validate section's raw data against file bounds
        // ------------------------------------------------------------------
        // Sections with zero PointerToRawData or zero SizeOfRawData are
        // valid (BSS / uninitialized data). Skip file-bounds check for those.
        if (sec.rawDataSize != 0 && sec.rawDataOffset != 0) {
            if (!PE::IsFileOffsetValid(sec.rawDataOffset, sec.rawDataSize, fileSize)) {
                return ErrorCode::MalformedPE;
            }
        }

        // ------------------------------------------------------------------
        // Validate section's virtual range against SizeOfImage
        // ------------------------------------------------------------------
        if (sec.virtualAddress > pe.sizeOfImage) {
            return ErrorCode::MalformedPE;
        }
        // Overflow-safe check: VA + VSize must not exceed SizeOfImage.
        // We allow equality (section ending exactly at SizeOfImage boundary).
        if (sec.virtualSize > pe.sizeOfImage - sec.virtualAddress) {
            return ErrorCode::MalformedPE;
        }

        pe.sections.push_back(sec);
    }

    // ------------------------------------------------------------------
    // Detect overlapping sections (by virtual address range).
    // O(n²) but n ≤ 96 — negligible.
    // ------------------------------------------------------------------
    const auto numSections = pe.sections.size();
    for (size_t a = 0; a < numSections; ++a) {
        for (size_t b = a + 1; b < numSections; ++b) {
            const auto& sa = pe.sections[a];
            const auto& sb = pe.sections[b];

            // Skip zero-sized sections (they can't overlap anything)
            if (sa.virtualSize == 0 || sb.virtualSize == 0) continue;

            const uint64_t aEnd = static_cast<uint64_t>(sa.virtualAddress) + sa.virtualSize;
            const uint64_t bEnd = static_cast<uint64_t>(sb.virtualAddress) + sb.virtualSize;

            // Two ranges [aStart, aEnd) and [bStart, bEnd) overlap iff
            // aStart < bEnd && bStart < aEnd.
            if (static_cast<uint64_t>(sa.virtualAddress) < bEnd &&
                static_cast<uint64_t>(sb.virtualAddress) < aEnd) {
                return ErrorCode::SectionOverflow;
            }
        }
    }

    return ErrorCode::Success;
}

// ============================================================================
// PEParser::ParseImports
// ============================================================================

ErrorCode PEParser::ParseImports(ByteSpan data, ParsedPE& pe) noexcept {
    // Check if import directory exists
    if (pe.numberOfDataDirectories <= PE::kDirImport) {
        return ErrorCode::Success; // No imports is valid
    }

    const auto& dir = pe.dataDirectories[PE::kDirImport];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return ErrorCode::Success;
    }

    // Convert import directory RVA to file offset
    const auto dirFileOff = RVAToFileOffset(pe, dir.VirtualAddress);
    if (!dirFileOff.has_value()) {
        return ErrorCode::MalformedPE;
    }

    const auto fileSize = static_cast<uint32_t>(data.size());
    uint64_t importDirEnd = static_cast<uint64_t>(dirFileOff.value()) + dir.Size;
    if (importDirEnd < dirFileOff.value()) {
        return ErrorCode::MalformedPE;
    }
    if (importDirEnd > fileSize) {
        importDirEnd = fileSize;
    }

    // Walk the import descriptor array. Each entry is 20 bytes.
    // The array is terminated by an all-zero descriptor.
    uint32_t descOffset = dirFileOff.value();
    uint32_t dllCount = 0;

    while (dllCount < PE::kMaxImportDLLs) {
        // Bounds check: room for one ImportDescriptor
        if (static_cast<uint64_t>(descOffset) + sizeof(PE::ImportDescriptor) > importDirEnd ||
            !PE::IsFileOffsetValid(descOffset, sizeof(PE::ImportDescriptor), fileSize)) {
            break; // Truncated table — accept what we have
        }

        PE::ImportDescriptor desc{};
        if (!SafeRead(data, descOffset, desc)) {
            break;
        }

        if (IsNullImportDescriptor(desc)) {
            break; // Normal terminator
        }

        // ---- Read DLL name ----
        if (desc.Name == 0) {
            return ErrorCode::MalformedPE;
        }
        const auto nameFileOff = RVAToFileOffset(pe, desc.Name);
        if (!nameFileOff.has_value()) {
            return ErrorCode::MalformedPE;
        }

        auto dllName = ReadString(data, nameFileOff.value(), PE::kMaxDLLNameLen);
        if (dllName.empty()) {
            return ErrorCode::MalformedPE;
        }

        ParsedImportDLL parsedDll;
        parsedDll.dllName = std::move(dllName);
        parsedDll.iatRVA  = desc.FirstThunk;

        // ---- Walk the Import Lookup Table (ILT) ----
        // Prefer OriginalFirstThunk; fall back to FirstThunk if OFT is 0
        // (some linkers produce PE files with OriginalFirstThunk == 0).
        uint32_t iltRVA = (desc.OriginalFirstThunk != 0)
                              ? desc.OriginalFirstThunk
                              : desc.FirstThunk;

        if (iltRVA == 0) {
            // Both zero — malformed but not fatal; skip this DLL's entries
            pe.imports.push_back(std::move(parsedDll));
            descOffset += sizeof(PE::ImportDescriptor);
            ++dllCount;
            continue;
        }

        const auto iltFileOff = RVAToFileOffset(pe, iltRVA);
        if (!iltFileOff.has_value()) {
            return ErrorCode::MalformedPE;
        }

        uint32_t entryOffset = iltFileOff.value();
        uint32_t entryCount = 0;

        if (pe.is64Bit) {
            // 64-bit ILT entries are 8 bytes each
            while (entryCount < PE::kMaxImportsPerDLL) {
                uint64_t thunk = 0;
                if (!SafeRead(data, entryOffset, thunk)) break;
                if (thunk == 0) break; // Null terminator

                ParsedImportEntry entry{};

                if (thunk & PE::kImportByOrdinal64) {
                    entry.byOrdinal = true;
                    entry.ordinal   = static_cast<uint16_t>(thunk & PE::kOrdinalMask16);
                } else {
                    // thunk is an RVA to an IMAGE_IMPORT_BY_NAME structure
                    const uint32_t hintNameRVA = static_cast<uint32_t>(thunk & 0x7FFFFFFFULL);
                    const auto hintFileOff = RVAToFileOffset(pe, hintNameRVA);
                    if (hintFileOff.has_value()) {
                        uint16_t hint = 0;
                        if (SafeRead(data, hintFileOff.value(), hint)) {
                            entry.hint = hint;
                            entry.name = ReadString(
                                data,
                                hintFileOff.value() + sizeof(uint16_t),
                                PE::kMaxExportNameLen);
                        }
                    }
                    // If hint/name lookup fails, we still record the entry
                    // with empty name — the loader will need to handle it.
                }

                parsedDll.entries.push_back(std::move(entry));
                if (entryOffset > fileSize - sizeof(uint64_t)) {
                    break;
                }
                entryOffset += sizeof(uint64_t);
                ++entryCount;
            }
        } else {
            // 32-bit ILT entries are 4 bytes each
            while (entryCount < PE::kMaxImportsPerDLL) {
                uint32_t thunk = 0;
                if (!SafeRead(data, entryOffset, thunk)) break;
                if (thunk == 0) break;

                ParsedImportEntry entry{};

                if (thunk & PE::kImportByOrdinal32) {
                    entry.byOrdinal = true;
                    entry.ordinal   = static_cast<uint16_t>(thunk & PE::kOrdinalMask16);
                } else {
                    const uint32_t hintNameRVA = thunk & 0x7FFFFFFFU;
                    const auto hintFileOff = RVAToFileOffset(pe, hintNameRVA);
                    if (hintFileOff.has_value()) {
                        uint16_t hint = 0;
                        if (SafeRead(data, hintFileOff.value(), hint)) {
                            entry.hint = hint;
                            entry.name = ReadString(
                                data,
                                hintFileOff.value() + sizeof(uint16_t),
                                PE::kMaxExportNameLen);
                        }
                    }
                }

                parsedDll.entries.push_back(std::move(entry));
                if (entryOffset > fileSize - sizeof(uint32_t)) {
                    break;
                }
                entryOffset += sizeof(uint32_t);
                ++entryCount;
            }
        }

        pe.imports.push_back(std::move(parsedDll));
        if (descOffset > fileSize - sizeof(PE::ImportDescriptor)) {
            break;
        }
        descOffset += sizeof(PE::ImportDescriptor);
        ++dllCount;
    }

    return ErrorCode::Success;
}

// ============================================================================
// PEParser::ParseExports
// ============================================================================

ErrorCode PEParser::ParseExports(ByteSpan data, ParsedPE& pe) noexcept {
    if (pe.numberOfDataDirectories <= PE::kDirExport) {
        return ErrorCode::Success;
    }

    const auto& dir = pe.dataDirectories[PE::kDirExport];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return ErrorCode::Success;
    }

    const auto edFileOff = RVAToFileOffset(pe, dir.VirtualAddress);
    if (!edFileOff.has_value()) {
        return ErrorCode::MalformedPE;
    }

    PE::ExportDirectory ed{};
    if (!SafeRead(data, edFileOff.value(), ed)) {
        return ErrorCode::MalformedPE;
    }

    // Validate counts
    if (ed.NumberOfFunctions > PE::kMaxExports) {
        return ErrorCode::MalformedPE;
    }
    if (ed.NumberOfNames > ed.NumberOfFunctions) {
        return ErrorCode::MalformedPE;
    }

    pe.exportOrdinalBase = ed.Base;

    // Read DLL name
    if (ed.Name != 0) {
        const auto nameOff = RVAToFileOffset(pe, ed.Name);
        if (nameOff.has_value()) {
            pe.exportDLLName = ReadString(data, nameOff.value(), PE::kMaxDLLNameLen);
        }
    }

    // ---- Read the three export arrays ----
    // AddressOfFunctions: array of uint32_t RVAs (NumberOfFunctions entries)
    // AddressOfNames:     array of uint32_t RVAs to name strings (NumberOfNames entries)
    // AddressOfNameOrdinals: array of uint16_t ordinal indices  (NumberOfNames entries)

    const auto funcTableOff = (ed.AddressOfFunctions != 0)
        ? RVAToFileOffset(pe, ed.AddressOfFunctions) : std::optional<uint32_t>{};
    const auto nameTableOff = (ed.AddressOfNames != 0)
        ? RVAToFileOffset(pe, ed.AddressOfNames) : std::optional<uint32_t>{};
    const auto ordTableOff  = (ed.AddressOfNameOrdinals != 0)
        ? RVAToFileOffset(pe, ed.AddressOfNameOrdinals) : std::optional<uint32_t>{};

    if (ed.NumberOfFunctions > 0 && !funcTableOff.has_value()) {
        return ErrorCode::MalformedPE;
    }
    if (ed.NumberOfNames > 0 && (!nameTableOff.has_value() || !ordTableOff.has_value())) {
        return ErrorCode::MalformedPE;
    }

    // Bounds-check the three arrays
    if (funcTableOff.has_value()) {
        if (!PE::IsFileOffsetValid(funcTableOff.value(),
                ed.NumberOfFunctions * sizeof(uint32_t),
                static_cast<uint32_t>(data.size()))) {
            return ErrorCode::MalformedPE;
        }
    }
    if (nameTableOff.has_value()) {
        if (!PE::IsFileOffsetValid(nameTableOff.value(),
                ed.NumberOfNames * sizeof(uint32_t),
                static_cast<uint32_t>(data.size()))) {
            return ErrorCode::MalformedPE;
        }
    }
    if (ordTableOff.has_value()) {
        if (!PE::IsFileOffsetValid(ordTableOff.value(),
                ed.NumberOfNames * sizeof(uint16_t),
                static_cast<uint32_t>(data.size()))) {
            return ErrorCode::MalformedPE;
        }
    }

    // Pre-read name→ordinal mapping into a temporary lookup.
    // nameOrdinals[i] gives the index into the function table for the i-th name.
    struct NameOrdPair {
        std::string name;
        uint16_t    funcIndex = 0;
    };
    std::vector<NameOrdPair> namedExports;
    if (ed.NumberOfNames > 0) {
        namedExports.reserve(ed.NumberOfNames);
        for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
            uint32_t nameRVA = 0;
            uint16_t ordIdx  = 0;
            const uint32_t nOff = nameTableOff.value() + i * sizeof(uint32_t);
            const uint32_t oOff = ordTableOff.value()  + i * sizeof(uint16_t);

            if (!SafeRead(data, nOff, nameRVA) || !SafeRead(data, oOff, ordIdx)) {
                return ErrorCode::MalformedPE;
            }

            // ordIdx must index into the function table
            if (ordIdx >= ed.NumberOfFunctions) {
                return ErrorCode::MalformedPE;
            }

            NameOrdPair nop;
            const auto fnameOff = RVAToFileOffset(pe, nameRVA);
            if (fnameOff.has_value()) {
                nop.name = ReadString(data, fnameOff.value(), PE::kMaxExportNameLen);
            }
            nop.funcIndex = ordIdx;
            namedExports.push_back(std::move(nop));
        }
    }

    // Export directory RVA range — used to detect forwarded exports.
    // A forwarded export has its function address RVA pointing *within* the
    // export directory itself (the forwarder string lives there).
    const uint32_t exportDirStart = dir.VirtualAddress;
    const uint64_t exportDirEnd64 = static_cast<uint64_t>(dir.VirtualAddress) + dir.Size;
    if (exportDirEnd64 > (std::numeric_limits<uint32_t>::max)()) {
        return ErrorCode::MalformedPE;
    }
    const uint32_t exportDirEnd = static_cast<uint32_t>(exportDirEnd64);

    // Build the export list: iterate over the function table
    pe.exports.reserve(ed.NumberOfFunctions);
    for (uint32_t funcIdx = 0; funcIdx < ed.NumberOfFunctions; ++funcIdx) {
        uint32_t funcRVA = 0;
        const uint32_t fOff = funcTableOff.value() + funcIdx * sizeof(uint32_t);
        if (!SafeRead(data, fOff, funcRVA)) {
            return ErrorCode::MalformedPE;
        }

        // Skip empty entries (unused ordinals)
        if (funcRVA == 0) continue;

        ParsedExportEntry entry{};
        if (funcIdx > (std::numeric_limits<uint32_t>::max)() - ed.Base) {
            return ErrorCode::MalformedPE;
        }
        entry.ordinal = funcIdx + ed.Base;

        // Check if this is a forwarded export
        if (funcRVA >= exportDirStart && funcRVA < exportDirEnd) {
            // Forwarded: funcRVA points to an ASCII string like "NTDLL.RtlInitString"
            const auto fwdOff = RVAToFileOffset(pe, funcRVA);
            if (fwdOff.has_value()) {
                entry.forwarder = ReadString(data, fwdOff.value(), PE::kMaxExportNameLen);
            }
            entry.rva = 0; // Forwarded — no actual address
        } else {
            entry.rva = funcRVA;
        }

        // Look up the name for this function index
        for (const auto& nop : namedExports) {
            if (nop.funcIndex == funcIdx) {
                entry.name = nop.name;
                break;
            }
        }

        pe.exports.push_back(std::move(entry));
    }

    return ErrorCode::Success;
}

// ============================================================================
// PEParser::ParseRelocations
// ============================================================================

ErrorCode PEParser::ParseRelocations(ByteSpan data, ParsedPE& pe) noexcept {
    if (pe.numberOfDataDirectories <= PE::kDirBaseReloc) {
        return ErrorCode::Success;
    }

    const auto& dir = pe.dataDirectories[PE::kDirBaseReloc];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return ErrorCode::Success;
    }

    const auto relocFileOff = RVAToFileOffset(pe, dir.VirtualAddress);
    if (!relocFileOff.has_value()) {
        return ErrorCode::MalformedPE;
    }

    pe.hasRelocations = true;

    const auto fileSize = static_cast<uint32_t>(data.size());
    uint32_t cursor = relocFileOff.value();

    // The relocation directory Size tells us the total byte length of all
    // relocation blocks. Compute the absolute end offset.
    const uint64_t relocEnd64 = static_cast<uint64_t>(cursor) + dir.Size;
    const uint32_t relocEnd = (relocEnd64 > fileSize)
                                  ? fileSize
                                  : static_cast<uint32_t>(relocEnd64);

    uint32_t blockCount = 0;
    uint32_t totalEntries = 0;

    while (cursor + sizeof(PE::BaseRelocation) <= relocEnd &&
           blockCount < PE::kMaxRelocBlocks)
    {
        PE::BaseRelocation blockHdr{};
        if (!SafeRead(data, cursor, blockHdr)) break;

        // SizeOfBlock must be at least the header (8 bytes) and reasonable
        if (blockHdr.SizeOfBlock < sizeof(PE::BaseRelocation)) break;
        if (blockHdr.SizeOfBlock > 0x00100000) { // 1 MB sanity cap per block
            return ErrorCode::MalformedPE;
        }

        // Number of 16-bit relocation entries in this block
        const uint32_t entryBytes = blockHdr.SizeOfBlock - sizeof(PE::BaseRelocation);
        const uint32_t numEntries = entryBytes / sizeof(uint16_t);

        if (numEntries > PE::kMaxRelocsPerBlock) {
            return ErrorCode::MalformedPE;
        }

        if (numEntries > kMaxTotalRelocEntries - totalEntries) {
            return ErrorCode::MalformedPE;
        }
        totalEntries += numEntries;

        // Bounds-check the block's raw data
        if (!PE::IsFileOffsetValid(cursor, blockHdr.SizeOfBlock, fileSize)) {
            break; // Truncated — accept what we have
        }

        ParsedRelocBlock parsedBlock;
        parsedBlock.pageRVA = blockHdr.VirtualAddress;
        parsedBlock.entries.reserve(numEntries);

        const uint32_t entriesStart = cursor + sizeof(PE::BaseRelocation);
        for (uint32_t i = 0; i < numEntries; ++i) {
            uint16_t raw = 0;
            if (!SafeRead(data, entriesStart + i * sizeof(uint16_t), raw)) break;

            const uint16_t type   = static_cast<uint16_t>(raw >> 12);
            const uint16_t offset = raw & 0x0FFF;
            parsedBlock.entries.emplace_back(type, offset);
        }

        pe.relocations.push_back(std::move(parsedBlock));

        // Advance cursor by block size (aligned to natural uint16 boundary)
        cursor += blockHdr.SizeOfBlock;
        ++blockCount;
    }

    return ErrorCode::Success;
}

// ============================================================================
// PEParser::ParseTLS
// ============================================================================

ErrorCode PEParser::ParseTLS(ByteSpan data, ParsedPE& pe) noexcept {
    if (pe.numberOfDataDirectories <= PE::kDirTLS) {
        return ErrorCode::Success;
    }

    const auto& dir = pe.dataDirectories[PE::kDirTLS];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return ErrorCode::Success;
    }

    const auto tlsDirFileOff = RVAToFileOffset(pe, dir.VirtualAddress);
    if (!tlsDirFileOff.has_value()) {
        return ErrorCode::MalformedPE;
    }

    pe.hasTLS = true;

    if (pe.is64Bit) {
        // ---- PE64 TLS ----
        PE::TLSDirectory64 tls{};
        if (!SafeRead(data, tlsDirFileOff.value(), tls)) {
            return ErrorCode::MalformedPE;
        }

        // TLS raw data addresses are VA (not RVA). Convert to RVA by
        // subtracting imageBase. Guard against underflow.
        if (tls.StartAddressOfRawData >= pe.imageBase) {
            pe.tlsRawDataStartRVA = static_cast<uint32_t>(tls.StartAddressOfRawData - pe.imageBase);
        }
        if (tls.EndAddressOfRawData > tls.StartAddressOfRawData) {
            const uint64_t rawSize = tls.EndAddressOfRawData - tls.StartAddressOfRawData;
            pe.tlsRawDataSize = (rawSize <= 0xFFFFFFFFULL)
                                    ? static_cast<uint32_t>(rawSize)
                                    : 0xFFFFFFFFU;
        }

        // Read callback array (array of 64-bit VAs terminated by zero)
        if (tls.AddressOfCallBacks != 0 && tls.AddressOfCallBacks >= pe.imageBase) {
            const uint32_t cbRVA = static_cast<uint32_t>(tls.AddressOfCallBacks - pe.imageBase);
            const auto cbFileOff = RVAToFileOffset(pe, cbRVA);
            if (cbFileOff.has_value()) {
                uint32_t off = cbFileOff.value();
                uint32_t cbCount = 0;
                while (cbCount < PE::kMaxTLSCallbacks) {
                    uint64_t cbAddr = 0;
                    if (!SafeRead(data, off, cbAddr)) break;
                    if (cbAddr == 0) break;
                    // Convert VA to RVA
                    if (cbAddr >= pe.imageBase &&
                        (cbAddr - pe.imageBase) <= (std::numeric_limits<uint32_t>::max)()) {
                        pe.tlsCallbackRVAs.push_back(
                            static_cast<uint32_t>(cbAddr - pe.imageBase));
                    }
                    off += sizeof(uint64_t);
                    ++cbCount;
                }
            }
        }
    } else {
        // ---- PE32 TLS ----
        PE::TLSDirectory32 tls{};
        if (!SafeRead(data, tlsDirFileOff.value(), tls)) {
            return ErrorCode::MalformedPE;
        }

        const auto imageBase32 = static_cast<uint32_t>(pe.imageBase);
        if (tls.StartAddressOfRawData >= imageBase32) {
            pe.tlsRawDataStartRVA = tls.StartAddressOfRawData - imageBase32;
        }
        if (tls.EndAddressOfRawData > tls.StartAddressOfRawData) {
            pe.tlsRawDataSize = tls.EndAddressOfRawData - tls.StartAddressOfRawData;
        }

        if (tls.AddressOfCallBacks != 0 && tls.AddressOfCallBacks >= imageBase32) {
            const uint32_t cbRVA = tls.AddressOfCallBacks - imageBase32;
            const auto cbFileOff = RVAToFileOffset(pe, cbRVA);
            if (cbFileOff.has_value()) {
                uint32_t off = cbFileOff.value();
                uint32_t cbCount = 0;
                while (cbCount < PE::kMaxTLSCallbacks) {
                    uint32_t cbAddr = 0;
                    if (!SafeRead(data, off, cbAddr)) break;
                    if (cbAddr == 0) break;
                    if (cbAddr >= imageBase32) {
                        pe.tlsCallbackRVAs.push_back(cbAddr - imageBase32);
                    }
                    off += sizeof(uint32_t);
                    ++cbCount;
                }
            }
        }
    }

    return ErrorCode::Success;
}

// ============================================================================
// PEParser::Parse  — Main entry point
// ============================================================================

ParseResult PEParser::Parse(ByteSpan data) noexcept {
    ParseResult result{};

    // ------------------------------------------------------------------
    // 0. File size cap
    // ------------------------------------------------------------------
    if (data.size() > PE::kMaxPEFileSize) {
        result.error = ErrorCode::PETooLarge;
        return result;
    }
    if (data.empty()) {
        result.error = ErrorCode::InvalidPESignature;
        return result;
    }

    const auto fileSize = static_cast<uint32_t>(data.size());
    result.pe.rawData = data;

    // ------------------------------------------------------------------
    // 1. DOS Header validation
    // ------------------------------------------------------------------
    {
        ErrorCode ec = ValidateDOSHeader(data);
        if (ec != ErrorCode::Success) {
            result.error = ec;
            return result;
        }
    }

    PE::DOSHeader dos{};
    (void)SafeRead(data, 0, dos); // Already validated above
    const auto peOffset = static_cast<uint32_t>(dos.e_lfanew);

    // ------------------------------------------------------------------
    // 2. NT Headers validation
    // ------------------------------------------------------------------
    {
        ErrorCode ec = ValidateNTHeaders(data, static_cast<int32_t>(peOffset));
        if (ec != ErrorCode::Success) {
            result.error = ec;
            return result;
        }
    }

    // ------------------------------------------------------------------
    // 3. Read FileHeader
    // ------------------------------------------------------------------
    const uint32_t fileHdrOffset = peOffset + sizeof(uint32_t);
    PE::FileHeader fileHdr{};
    if (!SafeRead(data, fileHdrOffset, fileHdr)) {
        result.error = ErrorCode::InvalidPEHeader;
        return result;
    }

    result.pe.machine       = fileHdr.Machine;
    result.pe.timeDateStamp = fileHdr.TimeDateStamp;
    result.pe.isDLL         = (fileHdr.Characteristics & PE::kCharDLL) != 0;

    const uint16_t numSections = fileHdr.NumberOfSections;
    const uint32_t optHdrOffset = fileHdrOffset + sizeof(PE::FileHeader);

    // ------------------------------------------------------------------
    // 4. Read Optional Header (PE32 or PE64)
    // ------------------------------------------------------------------
    uint16_t optMagic = 0;
    if (!SafeRead(data, optHdrOffset, optMagic)) {
        result.error = ErrorCode::InvalidPEHeader;
        return result;
    }

    uint32_t sectionTableOffset = 0;

    if (optMagic == PE::kPE64Magic) {
        // ---- PE64 Optional Header ----
        result.pe.is64Bit = true;

        PE::OptionalHeader64 opt{};
        // Read only what SizeOfOptionalHeader allows, zero-filling the rest
        const uint32_t readSize = (fileHdr.SizeOfOptionalHeader < sizeof(opt))
                                      ? fileHdr.SizeOfOptionalHeader
                                      : static_cast<uint32_t>(sizeof(opt));
        if (!PE::IsFileOffsetValid(optHdrOffset, readSize, fileSize)) {
            result.error = ErrorCode::InvalidPEHeader;
            return result;
        }
        std::memset(&opt, 0, sizeof(opt));
        std::memcpy(&opt, data.data() + optHdrOffset, readSize);

        result.pe.entryPointRVA      = opt.AddressOfEntryPoint;
        result.pe.imageBase          = opt.ImageBase;
        result.pe.sectionAlignment   = opt.SectionAlignment;
        result.pe.fileAlignment      = opt.FileAlignment;
        result.pe.sizeOfImage        = opt.SizeOfImage;
        result.pe.sizeOfHeaders      = opt.SizeOfHeaders;
        result.pe.subsystem          = opt.Subsystem;
        result.pe.dllCharacteristics = opt.DllCharacteristics;
        result.pe.stackReserve       = opt.SizeOfStackReserve;
        result.pe.stackCommit        = opt.SizeOfStackCommit;
        result.pe.heapReserve        = opt.SizeOfHeapReserve;
        result.pe.heapCommit         = opt.SizeOfHeapCommit;
        result.pe.checksum           = opt.CheckSum;

        // Number of data directories — cap to kMaxDataDirectories
        uint32_t numDirs = opt.NumberOfRvaAndSizes;
        if (numDirs > PE::kMaxDataDirectories) {
            numDirs = PE::kMaxDataDirectories;
        }
        result.pe.numberOfDataDirectories = numDirs;

        // Validate that the declared number of data directories actually fit
        // within SizeOfOptionalHeader.
        // Fixed fields before DataDirectories: 112 bytes for PE64
        static constexpr uint32_t kFixedPartSize64 = 112;
        const uint32_t dirSpaceAvail =
            (fileHdr.SizeOfOptionalHeader > kFixedPartSize64)
                ? (fileHdr.SizeOfOptionalHeader - kFixedPartSize64)
                : 0;
        const uint32_t dirsFit = dirSpaceAvail / sizeof(PE::DataDirectory);
        if (numDirs > dirsFit) {
            numDirs = dirsFit;
            result.pe.numberOfDataDirectories = numDirs;
        }

        for (uint32_t i = 0; i < numDirs; ++i) {
            result.pe.dataDirectories[i] = opt.DataDirectories[i];
        }

        sectionTableOffset = optHdrOffset + fileHdr.SizeOfOptionalHeader;

    } else if (optMagic == PE::kPE32Magic) {
        // ---- PE32 Optional Header ----
        result.pe.is64Bit = false;

        PE::OptionalHeader32 opt{};
        const uint32_t readSize = (fileHdr.SizeOfOptionalHeader < sizeof(opt))
                                      ? fileHdr.SizeOfOptionalHeader
                                      : static_cast<uint32_t>(sizeof(opt));
        if (!PE::IsFileOffsetValid(optHdrOffset, readSize, fileSize)) {
            result.error = ErrorCode::InvalidPEHeader;
            return result;
        }
        std::memset(&opt, 0, sizeof(opt));
        std::memcpy(&opt, data.data() + optHdrOffset, readSize);

        result.pe.entryPointRVA      = opt.AddressOfEntryPoint;
        result.pe.imageBase          = opt.ImageBase;
        result.pe.sectionAlignment   = opt.SectionAlignment;
        result.pe.fileAlignment      = opt.FileAlignment;
        result.pe.sizeOfImage        = opt.SizeOfImage;
        result.pe.sizeOfHeaders      = opt.SizeOfHeaders;
        result.pe.subsystem          = opt.Subsystem;
        result.pe.dllCharacteristics = opt.DllCharacteristics;
        result.pe.stackReserve       = opt.SizeOfStackReserve;
        result.pe.stackCommit        = opt.SizeOfStackCommit;
        result.pe.heapReserve        = opt.SizeOfHeapReserve;
        result.pe.heapCommit         = opt.SizeOfHeapCommit;
        result.pe.checksum           = opt.CheckSum;

        uint32_t numDirs = opt.NumberOfRvaAndSizes;
        if (numDirs > PE::kMaxDataDirectories) {
            numDirs = PE::kMaxDataDirectories;
        }
        result.pe.numberOfDataDirectories = numDirs;

        static constexpr uint32_t kFixedPartSize32 = 96;
        const uint32_t dirSpaceAvail =
            (fileHdr.SizeOfOptionalHeader > kFixedPartSize32)
                ? (fileHdr.SizeOfOptionalHeader - kFixedPartSize32)
                : 0;
        const uint32_t dirsFit = dirSpaceAvail / sizeof(PE::DataDirectory);
        if (numDirs > dirsFit) {
            numDirs = dirsFit;
            result.pe.numberOfDataDirectories = numDirs;
        }

        for (uint32_t i = 0; i < numDirs; ++i) {
            result.pe.dataDirectories[i] = opt.DataDirectories[i];
        }

        sectionTableOffset = optHdrOffset + fileHdr.SizeOfOptionalHeader;

    } else {
        result.error = ErrorCode::InvalidPEHeader;
        return result;
    }

    // ------------------------------------------------------------------
    // 5. Validate alignment fields
    // ------------------------------------------------------------------
    // FileAlignment must be a power of 2 in [512, 65536]
    if (!IsPowerOfTwo(result.pe.fileAlignment) ||
        result.pe.fileAlignment < 512 ||
        result.pe.fileAlignment > 65536) {
        result.error = ErrorCode::MalformedPE;
        return result;
    }

    // SectionAlignment must be a power of 2 and >= FileAlignment.
    // Special case: some linkers emit SectionAlignment == FileAlignment (no
    // virtual alignment). Windows loader accepts this when both are < 4096.
    if (!IsPowerOfTwo(result.pe.sectionAlignment)) {
        result.error = ErrorCode::MalformedPE;
        return result;
    }
    if (result.pe.sectionAlignment < result.pe.fileAlignment &&
        result.pe.sectionAlignment >= 4096) {
        // Only reject if sectionAlignment >= page size but < fileAlignment.
        // Some old/packed PEs have SectionAlignment == FileAlignment == 512.
        result.error = ErrorCode::MalformedPE;
        return result;
    }

    // ------------------------------------------------------------------
    // 6. Validate SizeOfImage and SizeOfHeaders
    // ------------------------------------------------------------------
    if (result.pe.sizeOfImage > kMaxSizeOfImage) {
        result.error = ErrorCode::PETooLarge;
        return result;
    }
    if (result.pe.sizeOfImage == 0) {
        result.error = ErrorCode::MalformedPE;
        return result;
    }
    if (result.pe.sizeOfHeaders > result.pe.sizeOfImage) {
        result.error = ErrorCode::MalformedPE;
        return result;
    }
    if (result.pe.sizeOfHeaders > fileSize) {
        result.error = ErrorCode::MalformedPE;
        return result;
    }

    // ------------------------------------------------------------------
    // 7. Parse sections
    // ------------------------------------------------------------------
    result.pe.sections.reserve(numSections);
    {
        ErrorCode ec = ParseSections(data, result.pe, sectionTableOffset, numSections);
        if (ec != ErrorCode::Success) {
            result.error = ec;
            return result;
        }
    }

    // ------------------------------------------------------------------
    // 8. Validate entry point
    // ------------------------------------------------------------------
    // Entry point of 0 is valid for DLLs (no DllMain) but not for EXEs.
    if (result.pe.entryPointRVA != 0) {
        // The entry point must fall within a section that has execute permission.
        bool entryInSection = false;
        for (const auto& sec : result.pe.sections) {
            const uint64_t vEnd = static_cast<uint64_t>(sec.virtualAddress) + sec.virtualSize;
            if (result.pe.entryPointRVA >= sec.virtualAddress &&
                result.pe.entryPointRVA < vEnd) {
                entryInSection = true;
                if (!HasProt(sec.protection, MemProt::Execute)) {
                    result.error = ErrorCode::InvalidEntryPoint;
                    return result;
                }
                break;
            }
        }
        if (!entryInSection) {
            // Some packed PEs have entry points in the header region. We allow
            // this only if it falls within SizeOfHeaders.
            if (result.pe.entryPointRVA >= result.pe.sizeOfHeaders) {
                result.error = ErrorCode::InvalidEntryPoint;
                return result;
            }
        }
    } else if (!result.pe.isDLL) {
        // Non-DLL with zero entry point — suspicious but some resource-only
        // PEs do this. Don't reject, but the emulator will detect no-op.
    }

    // ------------------------------------------------------------------
    // 9. Parse imports
    // ------------------------------------------------------------------
    {
        ErrorCode ec = ParseImports(data, result.pe);
        if (ec != ErrorCode::Success) {
            result.error = ec;
            return result;
        }
    }

    // ------------------------------------------------------------------
    // 10. Parse exports
    // ------------------------------------------------------------------
    {
        ErrorCode ec = ParseExports(data, result.pe);
        if (ec != ErrorCode::Success) {
            result.error = ec;
            return result;
        }
    }

    // ------------------------------------------------------------------
    // 11. Parse relocations
    // ------------------------------------------------------------------
    {
        ErrorCode ec = ParseRelocations(data, result.pe);
        if (ec != ErrorCode::Success) {
            result.error = ec;
            return result;
        }
    }

    // ------------------------------------------------------------------
    // 12. Parse TLS
    // ------------------------------------------------------------------
    {
        ErrorCode ec = ParseTLS(data, result.pe);
        if (ec != ErrorCode::Success) {
            result.error = ec;
            return result;
        }
    }

    result.error = ErrorCode::Success;
    return result;
}

} // namespace Phantom
