/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MetadataParser.hpp — .NET/CLR metadata parser for guest PE images
 *
 * Parses ECMA-335 metadata from .NET assemblies loaded in the emulated
 * guest address space. Extracts type definitions, method definitions,
 * member references, P/Invoke imports, assembly references, and heap
 * data (strings, user strings, blobs) needed for behavioral analysis
 * of managed malware.
 *
 * All parsing is defensive: corrupt, truncated, or adversarial metadata
 * is handled gracefully without crashing the emulator.
 *
 * References:
 *   ECMA-335 (6th Edition) §II.22–II.24 — Metadata Physical Layout
 *   Microsoft PE/COFF Specification — .NET Metadata
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "CLRTypes.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../Loader/PEStructures.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Phantom::CLR {

// ============================================================================
// MetadataParser — One instance per .NET assembly analysis
// ============================================================================
/**
 * @brief Defensive ECMA-335 metadata parser for guest .NET PE images.
 *
 * The parser copies bounded metadata streams from VirtualMemory, validates all
 * offsets/counts/index widths before use, and exposes capped table/heap views
 * for downstream MSIL and .NET behavior analysis.
 *
 * Thread safety: not thread-safe; use one parser per analysis thread. The
 * VirtualMemory reference is only used during Parse(). IRQL: user-mode only.
 * Failure contract: Parse() and public noexcept readers return false/empty
 * results on corrupt metadata or allocation failure, leaving parser state reset.
 */
class MetadataParser {
public:
    MetadataParser() noexcept = default;
    ~MetadataParser() noexcept = default;

    MetadataParser(const MetadataParser&) = delete;
    MetadataParser& operator=(const MetadataParser&) = delete;
    MetadataParser(MetadataParser&&) noexcept = default;
    MetadataParser& operator=(MetadataParser&&) noexcept = default;

    // ========================================================================
    // Core API
    // ========================================================================

    /**
     * @brief Parses .NET metadata from a PE loaded at imageBase in guest memory.
     * @param memory Guest virtual memory containing the mapped PE image.
     * @param imageBase Guest image base address.
     * @return true when CLR metadata was parsed successfully; false for native,
     * truncated, malformed, or resource-exhaustion cases.
     */
    [[nodiscard]] bool Parse(VirtualMemory& memory, GuestAddress imageBase) noexcept;

    /** @return true after a successful Parse() call. */
    [[nodiscard]] bool IsValid() const noexcept;

    // ========================================================================
    // Metadata Structure Accessors
    // ========================================================================

    [[nodiscard]] const COR20Header& GetCOR20Header() const noexcept;
    [[nodiscard]] const MetadataRoot& GetMetadataRoot() const noexcept;
    [[nodiscard]] uint32_t GetTableRowCount(MetadataTableId table) const noexcept;

    // ========================================================================
    // Parsed Table Accessors
    // ========================================================================

    [[nodiscard]] const std::vector<TypeDefRow>& GetTypeDefs() const noexcept;
    [[nodiscard]] const std::vector<MethodDefRow>& GetMethodDefs() const noexcept;
    [[nodiscard]] const std::vector<MemberRefRow>& GetMemberRefs() const noexcept;
    [[nodiscard]] const std::vector<TypeRefRow>& GetTypeRefs() const noexcept;
    [[nodiscard]] const std::vector<AssemblyRefRow>& GetAssemblyRefs() const noexcept;
    [[nodiscard]] std::optional<AssemblyRow> GetAssembly() const noexcept;
    [[nodiscard]] const std::vector<ImplMapRow>& GetImplMaps() const noexcept;
    [[nodiscard]] const std::vector<ModuleRefRow>& GetModuleRefs() const noexcept;
    [[nodiscard]] const std::vector<FieldRVARow>& GetFieldRVAs() const noexcept;

    // ========================================================================
    // Heap Access
    // ========================================================================

    /**
     * @brief Reads a null-terminated UTF-8 string from #Strings.
     * @return Empty string for offset 0, out-of-range offsets, or allocation failure.
     */
    [[nodiscard]] std::string ReadString(uint32_t heapOffset) const noexcept;

    /**
     * @brief Reads a UTF-16LE user string from #US with compressed-length prefix.
     * @return Empty string for malformed length encodings, odd byte counts, or caps.
     */
    [[nodiscard]] std::u16string ReadUserString(uint32_t heapOffset) const noexcept;

    /**
     * @brief Reads a bounded blob from #Blob with compressed-length prefix.
     * @return Empty vector for malformed lengths, zero-length blobs, or caps.
     */
    [[nodiscard]] std::vector<uint8_t> ReadBlob(uint32_t heapOffset) const noexcept;

    // ========================================================================
    // Resolution Helpers
    // ========================================================================

    /**
     * @brief Resolves a metadata token to "Namespace.Type::Method" style text.
     * @return Empty string if the token is invalid, unresolved, or allocation fails.
     */
    [[nodiscard]] std::string ResolveToken(MetadataToken token) const noexcept;

    /**
     * @brief Gets the guest address of a MethodDef IL body as imageBase + RVA.
     * @return nullopt for invalid method indexes, abstract/extern methods, or overflow.
     */
    [[nodiscard]] std::optional<GuestAddress> GetMethodBodyAddress(uint32_t methodIndex) const noexcept;

    /**
     * @brief Enumerates bounded user strings from the #US heap.
     * @return Parsed UTF-16 strings, capped by kMaxParsedStrings.
     */
    [[nodiscard]] std::vector<std::u16string> GetAllUserStrings() const noexcept;

private:
    // ========================================================================
    // State
    // ========================================================================

    bool         m_valid     = false;
    GuestAddress m_imageBase = 0;

    COR20Header  m_cor20{};
    MetadataRoot m_metadataRoot{};

    // Heap data copied from guest memory during Parse()
    std::vector<uint8_t> m_stringsHeap;
    std::vector<uint8_t> m_blobHeap;
    std::vector<uint8_t> m_guidHeap;
    std::vector<uint8_t> m_usHeap;
    std::vector<uint8_t> m_tildeData;

    // Row counts for all tables (from #~ header)
    std::array<uint32_t, kMaxMetadataTables> m_rowCounts{};

    // Precomputed row sizes for all tables
    std::array<uint32_t, kMaxMetadataTables> m_tableRowSizes{};

    // Byte offset within m_tildeData where row data begins
    uint32_t m_tableDataOffset = 0;

    // Heap index sizes (2 or 4, derived from HeapSizes byte)
    uint8_t m_stringIdxSize = 2;
    uint8_t m_guidIdxSize   = 2;
    uint8_t m_blobIdxSize   = 2;

    // Precomputed coded index sizes (ECMA-335 §II.24.2.6)
    uint8_t m_typeDefOrRefSize        = 2;
    uint8_t m_hasConstantSize         = 2;
    uint8_t m_hasCustomAttributeSize  = 2;
    uint8_t m_hasFieldMarshalSize     = 2;
    uint8_t m_hasDeclSecuritySize     = 2;
    uint8_t m_memberRefParentSize     = 2;
    uint8_t m_hasSemanticsSize        = 2;
    uint8_t m_methodDefOrRefSize      = 2;
    uint8_t m_memberForwardedSize     = 2;
    uint8_t m_implementationSize      = 2;
    uint8_t m_customAttributeTypeSize = 2;
    uint8_t m_resolutionScopeSize     = 2;
    uint8_t m_typeOrMethodDefSize     = 2;

    // Parsed table rows
    std::vector<TypeDefRow>     m_typeDefs;
    std::vector<MethodDefRow>   m_methodDefs;
    std::vector<MemberRefRow>   m_memberRefs;
    std::vector<TypeRefRow>     m_typeRefs;
    std::vector<AssemblyRefRow> m_assemblyRefs;
    std::optional<AssemblyRow>  m_assembly;
    std::vector<ImplMapRow>     m_implMaps;
    std::vector<ModuleRefRow>   m_moduleRefs;
    std::vector<FieldRVARow>    m_fieldRVAs;

    // ========================================================================
    // Internal Parsing Stages
    // ========================================================================

    void Reset() noexcept;

    [[nodiscard]] bool ParsePEHeaders(
        VirtualMemory& mem, uint32_t& clrRVA, uint32_t& clrSize) noexcept;

    [[nodiscard]] bool ParseCOR20(
        VirtualMemory& mem, uint32_t clrRVA, uint32_t clrSize) noexcept;

    [[nodiscard]] bool ParseMetadataBlob(VirtualMemory& mem);

    [[nodiscard]] bool ParseTildeHeader() noexcept;

    void ComputeCodedIndexSizes() noexcept;

    [[nodiscard]] bool ComputeTableRowSizes() noexcept;

    [[nodiscard]] bool ParseAllTables();

    // ========================================================================
    // Index Size Helpers
    // ========================================================================

    [[nodiscard]] uint8_t SimpleIdxSize(MetadataTableId table) const noexcept;

    [[nodiscard]] uint8_t CodedIdxSize(
        const MetadataTableId* tables,
        uint8_t tableCount,
        uint8_t tagBits) const noexcept;

    [[nodiscard]] uint32_t ComputeRowSize(uint8_t tableId) const noexcept;

    [[nodiscard]] std::string ReadStringHeap(uint32_t offset) const;

    [[nodiscard]] uint32_t DecodeBlobLength(
        const uint8_t* ptr, uint32_t remaining,
        uint32_t& headerSize) const noexcept;
};

} // namespace Phantom::CLR
