/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * PEParser.hpp — PE32/PE64 parser with exhaustive validation
 *
 * Parses raw Portable Executable files into a normalized structure suitable
 * for loading into the PhantomEmulator guest address space. Every field is
 * validated under the assumption that input is hostile — nation-state malware,
 * fuzzer output, or adversarial PE mutations designed to crash parsers.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "PEStructures.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>

namespace Phantom {

// ============================================================================
// Parsed PE Sub-Structures
// ============================================================================

struct ParsedSection {
    char     name[9]{};             // Null-terminated copy (8 chars max + NUL)
    uint32_t virtualAddress  = 0;
    uint32_t virtualSize     = 0;
    uint32_t rawDataOffset   = 0;
    uint32_t rawDataSize     = 0;
    uint32_t characteristics = 0;
    MemProt  protection      = MemProt::None;
};

struct ParsedImportEntry {
    std::string name;               // Function name (empty if by ordinal)
    uint16_t    ordinal   = 0;      // Ordinal value (0 if by name)
    uint16_t    hint      = 0;      // Hint value from Import-By-Name
    bool        byOrdinal = false;
};

struct ParsedImportDLL {
    std::string dllName;
    uint32_t    iatRVA = 0;         // RVA of this DLL's IAT entries
    std::vector<ParsedImportEntry> entries;
};

struct ParsedExportEntry {
    std::string name;
    uint32_t    ordinal   = 0;
    uint32_t    rva       = 0;      // 0 if forwarded
    std::string forwarder;          // Non-empty if forwarded export
};

struct ParsedRelocBlock {
    uint32_t pageRVA = 0;
    std::vector<std::pair<uint16_t, uint16_t>> entries; // (type, offset)
};

// ============================================================================
// ParsedPE — Fully-validated, normalized PE image descriptor
// ============================================================================

struct ParsedPE {
    bool     is64Bit            = false;
    bool     isDLL              = false;
    uint16_t machine            = 0;
    uint32_t entryPointRVA      = 0;
    uint64_t imageBase          = 0;
    uint32_t sectionAlignment   = 0;
    uint32_t fileAlignment      = 0;
    uint32_t sizeOfImage        = 0;
    uint32_t sizeOfHeaders      = 0;
    uint16_t subsystem          = 0;
    uint16_t dllCharacteristics = 0;
    uint64_t stackReserve       = 0;
    uint64_t stackCommit        = 0;
    uint64_t heapReserve        = 0;
    uint64_t heapCommit         = 0;
    uint32_t checksum           = 0;
    uint32_t timeDateStamp      = 0;

    // Data directories (RVA + size pairs)
    PE::DataDirectory dataDirectories[PE::kMaxDataDirectories]{};
    uint32_t          numberOfDataDirectories = 0;

    // Sections
    std::vector<ParsedSection> sections;

    // Imports
    std::vector<ParsedImportDLL> imports;

    // Exports
    std::vector<ParsedExportEntry> exports;
    std::string exportDLLName;
    uint32_t    exportOrdinalBase = 0;

    // Relocations
    std::vector<ParsedRelocBlock> relocations;
    bool hasRelocations = false;

    // TLS
    bool     hasTLS              = false;
    uint32_t tlsRawDataStartRVA = 0;
    uint32_t tlsRawDataSize     = 0;
    std::vector<uint32_t> tlsCallbackRVAs;

    // Raw reference to original data (NOT owned)
    ByteSpan rawData;
};

// ============================================================================
// ParseResult — Error-or-value return type (no std::expected dependency)
// ============================================================================

struct ParseResult {
    ParsedPE  pe;
    ErrorCode error = ErrorCode::Success;

    [[nodiscard]] bool Ok() const noexcept { return error == ErrorCode::Success; }
};

// ============================================================================
// PEParser — Static PE32/PE64 parser with exhaustive hostile-input validation
// ============================================================================

class PEParser {
public:
    /// Parse a raw PE file buffer. Returns ParseResult containing ParsedPE or ErrorCode.
    [[nodiscard]] static ParseResult Parse(ByteSpan data) noexcept;

    /// Quick check: does this buffer begin with a valid MZ + PE signature?
    [[nodiscard]] static bool IsPE(ByteSpan data) noexcept;

    /// Quick check: is this PE64? Returns nullopt if not a valid PE.
    [[nodiscard]] static std::optional<bool> Is64Bit(ByteSpan data) noexcept;

    /// RVA-to-file-offset conversion using the parsed section table.
    [[nodiscard]] static std::optional<uint32_t> RVAToFileOffset(
        const ParsedPE& pe, uint32_t rva) noexcept;

    /// Read a null-terminated ASCII string from a file offset (capped length).
    [[nodiscard]] static std::string ReadString(
        ByteSpan data, uint32_t fileOffset, uint32_t maxLen = 260) noexcept;

private:
    [[nodiscard]] static ErrorCode ValidateDOSHeader(ByteSpan data) noexcept;
    [[nodiscard]] static ErrorCode ValidateNTHeaders(ByteSpan data, int32_t peOffset) noexcept;
    [[nodiscard]] static ErrorCode ParseSections(
        ByteSpan data, ParsedPE& pe, uint32_t sectionTableOffset,
        uint16_t sectionCount) noexcept;
    [[nodiscard]] static ErrorCode ParseImports(ByteSpan data, ParsedPE& pe) noexcept;
    [[nodiscard]] static ErrorCode ParseExports(ByteSpan data, ParsedPE& pe) noexcept;
    [[nodiscard]] static ErrorCode ParseRelocations(ByteSpan data, ParsedPE& pe) noexcept;
    [[nodiscard]] static ErrorCode ParseTLS(ByteSpan data, ParsedPE& pe) noexcept;
};

} // namespace Phantom
