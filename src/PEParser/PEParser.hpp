#pragma once
/**
 * @file PEParser.hpp
 * @brief Enterprise-grade PE (Portable Executable) parser for ShadowStrike.
 *
 * This is the main public API for PE file parsing. It provides:
 * - Safe parsing of potentially hostile PE files
 * - Comprehensive bounds checking and overflow protection
 * - Lazy parsing of imports/exports/resources for performance
 * - Detailed anomaly detection for malware analysis
 * - PIMPL pattern for ABI stability
 *
 * @note All parsing operations are noexcept and report errors via PEError.
 * @warning Never trust parsed values without validation - this parser
 *          is designed to handle malicious input safely.
 *
 * @copyright ShadowStrike Security Suite
 */

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <span>

#include "PEConstants.hpp"
#include "PETypes.hpp"
#include "PEValidation.hpp"
#include "SafeReader.hpp"

namespace ShadowStrike {
namespace PEParser {

// Forward declaration for PIMPL
class PEParserImpl;

// ============================================================================
// Parsed Information Structures
// ============================================================================

/**
 * @brief Information about a parsed PE section.
 */
struct SectionInfo {
    std::string name;               ///< Section name (max 8 chars)
    uint32_t virtualAddress = 0;    ///< RVA in memory
    uint32_t virtualSize = 0;       ///< Size in memory
    uint32_t rawAddress = 0;        ///< File offset (PointerToRawData)
    uint32_t rawSize = 0;           ///< Size in file (SizeOfRawData)
    uint32_t characteristics = 0;   ///< Section flags

    // Computed flags
    bool isExecutable = false;      ///< Has MEM_EXECUTE
    bool isWritable = false;        ///< Has MEM_WRITE
    bool isReadable = false;        ///< Has MEM_READ
    bool hasCode = false;           ///< Has CNT_CODE
    bool hasInitializedData = false;///< Has CNT_INITIALIZED_DATA
    bool hasUninitializedData = false; ///< Has CNT_UNINITIALIZED_DATA

    // Analysis results
    double entropy = 0.0;           ///< Shannon entropy (0.0-8.0)
    bool isPackedHeuristic = false; ///< High entropy suggests packing

    // Detected anomalies
    std::vector<Anomaly> anomalies;
};

/**
 * @brief Information about a data directory.
 */
struct DataDirectoryInfo {
    uint32_t rva = 0;               ///< Relative virtual address
    uint32_t size = 0;              ///< Size in bytes
    bool present = false;           ///< True if RVA and size are non-zero
    std::optional<size_t> fileOffset; ///< Computed file offset
};

/**
 * @brief Information about an imported function.
 */
struct ImportFunctionInfo {
    std::string name;               ///< Function name (empty if by ordinal)
    uint16_t ordinal = 0;           ///< Ordinal number
    bool byOrdinal = false;         ///< True if imported by ordinal
    uint64_t iatRva = 0;            ///< RVA of IAT entry
    uint16_t hint = 0;              ///< Hint for name lookup
};

/**
 * @brief Information about an imported DLL.
 */
struct ImportInfo {
    std::wstring dllName;           ///< DLL name
    std::vector<ImportFunctionInfo> functions; ///< Imported functions
    bool isBoundImport = false;     ///< Has pre-resolved addresses
    bool isDelayLoad = false;       ///< Delay-loaded import
    uint32_t originalFirstThunk = 0;///< RVA of INT
    uint32_t firstThunk = 0;        ///< RVA of IAT
};

/**
 * @brief Information about an exported function.
 */
struct ExportInfo {
    std::string name;               ///< Export name (may be empty)
    uint32_t ordinal = 0;           ///< Ordinal number
    uint32_t rva = 0;               ///< RVA of function
    bool isForwarder = false;       ///< True if forwarded
    std::string forwarderName;      ///< Forwarder string (e.g., "NTDLL.RtlCopyMemory")
    bool byName = false;            ///< Exported by name
};

/**
 * @brief Export directory information.
 */
struct ExportDirectoryInfo {
    std::wstring dllName;           ///< DLL name
    uint32_t ordinalBase = 0;       ///< Starting ordinal number
    uint32_t numberOfFunctions = 0; ///< Number of functions
    uint32_t numberOfNames = 0;     ///< Number of named exports
    std::vector<ExportInfo> exports;///< Export entries
};

/**
 * @brief TLS (Thread Local Storage) information.
 */
struct TLSInfo {
    uint64_t startAddressOfRawData = 0;
    uint64_t endAddressOfRawData = 0;
    uint64_t addressOfIndex = 0;
    uint64_t addressOfCallbacks = 0;
    std::vector<uint64_t> callbacks; ///< TLS callback addresses
    uint32_t sizeOfZeroFill = 0;
    uint32_t characteristics = 0;
};

/**
 * @brief Relocation entry.
 */
struct RelocationEntry {
    uint32_t rva = 0;               ///< Virtual address to relocate
    uint16_t type = 0;              ///< Relocation type
};

/**
 * @brief Relocation block.
 */
struct RelocationBlock {
    uint32_t pageRva = 0;           ///< Base RVA for this block
    std::vector<RelocationEntry> entries;
};

/**
 * @brief Debug directory entry.
 */
struct DebugInfo {
    uint32_t type = 0;              ///< Debug type
    uint32_t timestamp = 0;         ///< Time/date stamp
    uint16_t majorVersion = 0;
    uint16_t minorVersion = 0;
    uint32_t sizeOfData = 0;
    uint32_t addressOfRawData = 0;  ///< RVA
    uint32_t pointerToRawData = 0;  ///< File offset

    // For CodeView debug info
    std::string pdbPath;            ///< Path to PDB file
    std::array<uint8_t, 16> pdbGuid = {};///< PDB GUID
    uint32_t pdbAge = 0;            ///< PDB age
};

/**
 * @brief Resource entry.
 */
struct ResourceEntry {
    uint32_t type = 0;              ///< Resource type
    uint32_t name = 0;              ///< Resource name/ID
    uint32_t language = 0;          ///< Language ID
    uint32_t offset = 0;            ///< File offset of data
    uint32_t size = 0;              ///< Size of data
    uint32_t codePage = 0;          ///< Code page
    bool nameIsString = false;      ///< Name is string, not ID
    std::wstring nameString;        ///< Name if nameIsString
};

/**
 * @brief Rich header entry (build tool info).
 */
struct RichEntry {
    uint16_t buildId = 0;           ///< Build ID (product)
    uint16_t productId = 0;         ///< Product ID
    uint32_t useCount = 0;          ///< Use count
};

/**
 * @brief Rich header information.
 */
struct RichHeaderInfo {
    bool present = false;           ///< Rich header found
    uint32_t checksum = 0;          ///< XOR key / checksum
    size_t offset = 0;              ///< File offset of Rich header
    size_t size = 0;                ///< Size of Rich header
    std::vector<RichEntry> entries; ///< Tool entries
    bool checksumValid = false;     ///< Checksum verification result
};

/**
 * @brief Complete parsed PE information.
 */
struct PEInfo {
    // Basic validity
    bool valid = false;             ///< True if basic parsing succeeded
    bool is64Bit = false;           ///< PE32+ (64-bit)
    bool isDotNet = false;          ///< Has CLR header
    bool isSigned = false;          ///< Has Authenticode signature
    bool isDLL = false;             ///< DLL flag set
    bool isDriver = false;          ///< Kernel-mode driver

    // Machine type
    uint16_t machine = 0;           ///< Target machine
    std::wstring machineString;     ///< Machine type as string

    // Image characteristics
    uint64_t imageBase = 0;         ///< Preferred base address
    uint32_t entryPointRva = 0;     ///< Entry point RVA
    uint32_t sizeOfImage = 0;       ///< Image size in memory
    uint32_t sizeOfHeaders = 0;     ///< Headers size
    uint32_t checksum = 0;          ///< PE checksum
    uint16_t subsystem = 0;         ///< Subsystem type
    uint16_t dllCharacteristics = 0;///< Security flags

    // Alignments
    uint32_t fileAlignment = 0;
    uint32_t sectionAlignment = 0;

    // Timestamps
    uint32_t timeDateStamp = 0;     ///< Compilation timestamp

    // Linker version
    uint8_t majorLinkerVersion = 0;
    uint8_t minorLinkerVersion = 0;

    // OS version
    uint16_t majorOsVersion = 0;
    uint16_t minorOsVersion = 0;

    // Sections
    std::vector<SectionInfo> sections;

    // Data directories
    std::array<DataDirectoryInfo, DataDirectory::MAX_ENTRIES> dataDirectories;

    // Entry point analysis
    std::optional<size_t> entryPointSectionIndex;
    bool entryPointInExecutableSection = false;

    // File information
    size_t fileSize = 0;            ///< Original file size
    size_t overlayOffset = 0;       ///< Offset of overlay data (0 if none)
    size_t overlaySize = 0;         ///< Size of overlay data

    // Detected anomalies
    std::vector<Anomaly> anomalies;

    // Parsing statistics
    uint64_t parseTimeNs = 0;       ///< Parsing time in nanoseconds
};

// ============================================================================
// Main Parser Class
// ============================================================================

/**
 * @brief Enterprise-grade PE file parser.
 *
 * This class provides safe, comprehensive parsing of PE files with
 * full bounds checking and overflow protection. It uses the PIMPL
 * pattern for ABI stability.
 *
 * Usage:
 * @code
 *   PEParser parser;
 *   PEInfo info;
 *   PEError err;
 *
 *   if (parser.ParseFile(L"C:\\Windows\\System32\\kernel32.dll", info, &err)) {
 *       // Use info.sections, info.entryPointRva, etc.
 *       std::vector<ImportInfo> imports;
 *       if (parser.ParseImports(imports)) {
 *           // Process imports
 *       }
 *   } else {
 *       // Handle error
 *       LogError(err.message);
 *   }
 * @endcode
 *
 * @note Thread-safe for parsing different files from different instances.
 * @note Single instance should only parse one file at a time.
 */
class PEParser {
public:
    /**
     * @brief Construct a new PE parser.
     */
    PEParser() noexcept;

    /**
     * @brief Destructor.
     */
    ~PEParser();

    // Non-copyable
    PEParser(const PEParser&) = delete;
    PEParser& operator=(const PEParser&) = delete;

    // Movable
    PEParser(PEParser&&) noexcept;
    PEParser& operator=(PEParser&&) noexcept;

    // ========================================================================
    // Primary Parsing Methods
    // ========================================================================

    /**
     * @brief Parse a PE file from disk.
     *
     * Uses memory mapping for optimal performance. This is the preferred
     * method for parsing files.
     *
     * @param path Path to the PE file.
     * @param out Output for parsed information.
     * @param err Optional error output.
     * @return true if basic parsing succeeded.
     */
    [[nodiscard]] bool ParseFile(const std::wstring& path,
                                  PEInfo& out,
                                  PEError* err = nullptr) noexcept;

    /**
     * @brief Parse a PE from a memory buffer.
     *
     * Zero-copy parsing of an in-memory PE image.
     *
     * @param data Pointer to PE data.
     * @param size Size of data in bytes.
     * @param out Output for parsed information.
     * @param err Optional error output.
     * @return true if basic parsing succeeded.
     */
    [[nodiscard]] bool ParseBuffer(const uint8_t* data,
                                    size_t size,
                                    PEInfo& out,
                                    PEError* err = nullptr) noexcept;

    /**
     * @brief Parse a PE from a span.
     *
     * @param data Span of PE data.
     * @param out Output for parsed information.
     * @param err Optional error output.
     * @return true if basic parsing succeeded.
     */
    [[nodiscard]] bool ParseBuffer(std::span<const uint8_t> data,
                                    PEInfo& out,
                                    PEError* err = nullptr) noexcept;

    // ========================================================================
    // Detailed Parsing (Lazy-loaded)
    // ========================================================================

    /**
     * @brief Parse import table.
     *
     * Must be called after successful ParseFile/ParseBuffer.
     *
     * @param out Output vector of import information.
     * @param err Optional error output.
     * @return true if parsing succeeded.
     */
    [[nodiscard]] bool ParseImports(std::vector<ImportInfo>& out,
                                     PEError* err = nullptr) noexcept;

    /**
     * @brief Parse export table.
     *
     * @param out Output for export directory information.
     * @param err Optional error output.
     * @return true if parsing succeeded.
     */
    [[nodiscard]] bool ParseExports(ExportDirectoryInfo& out,
                                     PEError* err = nullptr) noexcept;

    /**
     * @brief Parse TLS directory.
     *
     * @param out Output for TLS information.
     * @param err Optional error output.
     * @return true if parsing succeeded.
     */
    [[nodiscard]] bool ParseTLS(TLSInfo& out,
                                 PEError* err = nullptr) noexcept;

    /**
     * @brief Parse resources.
     *
     * @param out Output vector of resource entries.
     * @param maxDepth Maximum recursion depth (default 16).
     * @param err Optional error output.
     * @return true if parsing succeeded.
     */
    [[nodiscard]] bool ParseResources(std::vector<ResourceEntry>& out,
                                       uint32_t maxDepth = 16,
                                       PEError* err = nullptr) noexcept;

    /**
     * @brief Parse relocations.
     *
     * @param out Output vector of relocation blocks.
     * @param err Optional error output.
     * @return true if parsing succeeded.
     */
    [[nodiscard]] bool ParseRelocations(std::vector<RelocationBlock>& out,
                                         PEError* err = nullptr) noexcept;

    /**
     * @brief Parse debug directory.
     *
     * @param out Output vector of debug entries.
     * @param err Optional error output.
     * @return true if parsing succeeded.
     */
    [[nodiscard]] bool ParseDebugInfo(std::vector<DebugInfo>& out,
                                       PEError* err = nullptr) noexcept;

    /**
     * @brief Parse Rich header.
     *
     * @param out Output for Rich header information.
     * @param err Optional error output.
     * @return true if Rich header found and parsed.
     */
    [[nodiscard]] bool ParseRichHeader(RichHeaderInfo& out,
                                        PEError* err = nullptr) noexcept;

    // ========================================================================
    // Address Translation
    // ========================================================================

    /**
     * @brief Convert RVA to file offset.
     *
     * @param rva Relative virtual address.
     * @return File offset, or nullopt if RVA is invalid.
     */
    [[nodiscard]] std::optional<size_t> RvaToOffset(uint32_t rva) const noexcept;

    /**
     * @brief Convert file offset to RVA.
     *
     * @param offset File offset.
     * @return RVA, or nullopt if offset is not in a section.
     */
    [[nodiscard]] std::optional<uint32_t> OffsetToRva(size_t offset) const noexcept;

    /**
     * @brief Check if RVA is within a valid section.
     *
     * @param rva Relative virtual address.
     * @return true if RVA is within any section's virtual range.
     */
    [[nodiscard]] bool IsValidRva(uint32_t rva) const noexcept;

    /**
     * @brief Get section index containing RVA.
     *
     * @param rva Relative virtual address.
     * @return Section index, or nullopt if not found.
     */
    [[nodiscard]] std::optional<size_t> GetSectionByRva(uint32_t rva) const noexcept;

    /**
     * @brief Get section index by name.
     *
     * @param name Section name (case-sensitive, max 8 chars).
     * @return Section index, or nullopt if not found.
     */
    [[nodiscard]] std::optional<size_t> GetSectionByName(
        std::string_view name) const noexcept;

    // ========================================================================
    // Validation
    // ========================================================================

    /**
     * @brief Perform deep validation of parsed PE.
     *
     * @param issues Output vector of validation issues.
     * @return true if no critical issues found.
     */
    [[nodiscard]] bool ValidatePE(std::vector<ValidationResult>& issues) const noexcept;

    /**
     * @brief Check if PE has a specific anomaly.
     *
     * @param type Anomaly type to check.
     * @return true if anomaly was detected.
     */
    [[nodiscard]] bool HasAnomaly(AnomalyType type) const noexcept;

    // ========================================================================
    // Raw Access
    // ========================================================================

    /**
     * @brief Get the underlying safe reader.
     *
     * @return Pointer to SafeReader, or nullptr if not parsed.
     */
    [[nodiscard]] const SafeReader* GetReader() const noexcept;

    /**
     * @brief Get parsed PE information.
     *
     * @return Pointer to PEInfo, or nullptr if not parsed.
     */
    [[nodiscard]] const PEInfo* GetInfo() const noexcept;

    /**
     * @brief Check if a file has been parsed.
     *
     * @return true if ParseFile/ParseBuffer succeeded.
     */
    [[nodiscard]] bool IsParsed() const noexcept;

    /**
     * @brief Reset parser state.
     *
     * Releases any memory-mapped file and clears parsed data.
     */
    void Reset() noexcept;

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * @brief Calculate section entropy.
     *
     * @param sectionIndex Index of section.
     * @return Entropy value (0.0-8.0), or -1.0 on error.
     */
    [[nodiscard]] double CalculateSectionEntropy(size_t sectionIndex) const noexcept;

    /**
     * @brief Calculate PE checksum and compare with header.
     *
     * @return true if checksum matches or is zero (not set).
     */
    [[nodiscard]] bool VerifyChecksum() const noexcept;

    /**
     * @brief Get machine type as human-readable string.
     *
     * @param machine Machine type value.
     * @return Machine type string.
     */
    [[nodiscard]] static std::wstring MachineToString(uint16_t machine) noexcept;

    /**
     * @brief Get subsystem as human-readable string.
     *
     * @param subsystem Subsystem value.
     * @return Subsystem string.
     */
    [[nodiscard]] static std::wstring SubsystemToString(uint16_t subsystem) noexcept;

private:
    std::unique_ptr<PEParserImpl> m_impl;
};

} // namespace PEParser
} // namespace ShadowStrike
