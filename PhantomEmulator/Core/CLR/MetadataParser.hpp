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
//
// Usage:
//   MetadataParser parser;
//   if (parser.Parse(memory, imageBase)) {
//       for (auto& td : parser.GetTypeDefs()) { ... }
//       for (auto& md : parser.GetMethodDefs()) { ... }
//   }
//
// Thread safety: NOT thread-safe. Each analysis thread should use its own
// parser instance. The VirtualMemory reference is only used during Parse().

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

    /// Parse .NET metadata from a PE loaded at imageBase in guest memory.
    /// Returns false if the PE is not a .NET assembly or metadata is corrupt.
    [[nodiscard]] bool Parse(VirtualMemory& memory, GuestAddress imageBase) noexcept;

    /// Check if parsing succeeded and this is a valid .NET assembly.
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

    /// Read a null-terminated UTF-8 string from the #Strings heap.
    [[nodiscard]] std::string ReadString(uint32_t heapOffset) const noexcept;

    /// Read a UTF-16LE user string from the #US heap (compressed-length prefix).
    [[nodiscard]] std::u16string ReadUserString(uint32_t heapOffset) const noexcept;

    /// Read a blob from the #Blob heap (compressed-length prefix).
    [[nodiscard]] std::vector<uint8_t> ReadBlob(uint32_t heapOffset) const noexcept;

    // ========================================================================
    // Resolution Helpers
    // ========================================================================

    /// Resolve a metadata token to a human-readable "Namespace.Type::Method" name.
    [[nodiscard]] std::string ResolveToken(MetadataToken token) const noexcept;

    /// Get the guest address of a MethodDef IL body (imageBase + RVA).
    [[nodiscard]] std::optional<GuestAddress> GetMethodBodyAddress(uint32_t methodIndex) const noexcept;

    /// Enumerate all user strings from the #US heap.
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
