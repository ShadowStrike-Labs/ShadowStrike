/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MetadataParser.cpp — .NET/CLR metadata parser implementation
 *
 * Production-grade ECMA-335 metadata parser operating on guest virtual
 * memory. Every offset, size, count, and index is validated before use.
 * Designed to survive adversarial .NET assemblies (obfuscated, packed,
 * ConfuserEx, dnGuard, nation-state tooling) without crashing.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MetadataParser.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace Phantom::CLR {

// ============================================================================
// File-local constants and helpers
// ============================================================================

namespace {

// Safety caps — reject metadata that exceeds these bounds
static constexpr uint32_t kMaxMetadataSize      = 64 * 1024 * 1024;
static constexpr uint32_t kMaxStreamSize         = 32 * 1024 * 1024;
static constexpr uint32_t kMaxVersionLength      = 256;
static constexpr uint32_t kMaxStreamNameLength   = 32;
static constexpr uint32_t kMaxStreamCount        = 16;
static constexpr uint32_t kMaxStringReadLength   = 1024;
static constexpr uint32_t kMaxBlobReadLength     = 1 * 1024 * 1024;
static constexpr uint32_t kMaxUserStringReadLen  = 65536;
static constexpr uint32_t kMaxRowsPerTable       = 1'000'000;
static constexpr uint32_t kMaxElfanew            = 1024 * 1024;
static constexpr uint32_t kMaxAssemblyRefs       = 4096;
static constexpr uint32_t kMaxMemberRefs         = 100000;
static constexpr uint32_t kMaxImplMaps           = 4096;
static constexpr uint32_t kMaxModuleRefs         = 256;
static constexpr uint32_t kMaxFieldRVAs          = 10000;

// ============================================================================
// Coded index family definitions (ECMA-335 §II.24.2.6)
// ============================================================================

static constexpr MetadataTableId kTypeDefOrRef[] = {
    MetadataTableId::TypeDef, MetadataTableId::TypeRef, MetadataTableId::TypeSpec
};
static constexpr uint8_t kTypeDefOrRefBits = 2;

static constexpr MetadataTableId kHasConstant[] = {
    MetadataTableId::Field, MetadataTableId::Param, MetadataTableId::Property
};
static constexpr uint8_t kHasConstantBits = 2;

static constexpr MetadataTableId kHasCustomAttribute[] = {
    MetadataTableId::MethodDef,   MetadataTableId::Field,
    MetadataTableId::TypeRef,     MetadataTableId::TypeDef,
    MetadataTableId::Param,       MetadataTableId::InterfaceImpl,
    MetadataTableId::MemberRef,   MetadataTableId::Module,
    MetadataTableId::DeclSecurity,MetadataTableId::Property,
    MetadataTableId::Event,       MetadataTableId::StandAloneSig,
    MetadataTableId::ModuleRef,   MetadataTableId::TypeSpec,
    MetadataTableId::Assembly,    MetadataTableId::AssemblyRef,
    MetadataTableId::File,        MetadataTableId::ExportedType,
    MetadataTableId::ManifestResource, MetadataTableId::GenericParam,
    MetadataTableId::GenericParamConstraint, MetadataTableId::MethodSpec
};
static constexpr uint8_t kHasCustomAttributeBits = 5;

static constexpr MetadataTableId kHasFieldMarshal[] = {
    MetadataTableId::Field, MetadataTableId::Param
};
static constexpr uint8_t kHasFieldMarshalBits = 1;

static constexpr MetadataTableId kHasDeclSecurity[] = {
    MetadataTableId::TypeDef, MetadataTableId::MethodDef, MetadataTableId::Assembly
};
static constexpr uint8_t kHasDeclSecurityBits = 2;

static constexpr MetadataTableId kMemberRefParent[] = {
    MetadataTableId::TypeDef,  MetadataTableId::TypeRef,
    MetadataTableId::ModuleRef,MetadataTableId::MethodDef,
    MetadataTableId::TypeSpec
};
static constexpr uint8_t kMemberRefParentBits = 3;

static constexpr MetadataTableId kHasSemantics[] = {
    MetadataTableId::Event, MetadataTableId::Property
};
static constexpr uint8_t kHasSemanticsBits = 1;

static constexpr MetadataTableId kMethodDefOrRef[] = {
    MetadataTableId::MethodDef, MetadataTableId::MemberRef
};
static constexpr uint8_t kMethodDefOrRefBits = 1;

static constexpr MetadataTableId kMemberForwarded[] = {
    MetadataTableId::Field, MetadataTableId::MethodDef
};
static constexpr uint8_t kMemberForwardedBits = 1;

static constexpr MetadataTableId kImplementation[] = {
    MetadataTableId::File, MetadataTableId::AssemblyRef, MetadataTableId::ExportedType
};
static constexpr uint8_t kImplementationBits = 2;

// CustomAttributeType: tags 0,1,3,4 unused; tag 2 = MethodDef, tag 3 is actually MemberRef
// Only MethodDef and MemberRef contribute to max-row computation.
static constexpr MetadataTableId kCustomAttributeType[] = {
    MetadataTableId::MethodDef, MetadataTableId::MemberRef
};
static constexpr uint8_t kCustomAttributeTypeBits = 3;

static constexpr MetadataTableId kResolutionScope[] = {
    MetadataTableId::Module, MetadataTableId::ModuleRef,
    MetadataTableId::AssemblyRef, MetadataTableId::TypeRef
};
static constexpr uint8_t kResolutionScopeBits = 2;

static constexpr MetadataTableId kTypeOrMethodDef[] = {
    MetadataTableId::TypeDef, MetadataTableId::MethodDef
};
static constexpr uint8_t kTypeOrMethodDefBits = 1;

// ============================================================================
// BufferCursor — bounds-checked sequential reader over a host byte buffer
// ============================================================================

struct BufferCursor {
    const uint8_t* data;
    uint32_t       size;
    uint32_t       pos;
    bool           ok;

    BufferCursor(const uint8_t* d, uint32_t s) noexcept
        : data(d), size(s), pos(0), ok(d != nullptr && s > 0) {}

    BufferCursor(const uint8_t* d, uint32_t s, uint32_t startPos) noexcept
        : data(d), size(s), pos(startPos), ok(d != nullptr && startPos <= s) {}

    [[nodiscard]] bool CanRead(uint32_t count) const noexcept {
        return ok && pos <= size && (size - pos) >= count;
    }

    uint8_t ReadU8() noexcept {
        if (!CanRead(1)) { ok = false; return 0; }
        return data[pos++];
    }

    uint16_t ReadU16() noexcept {
        if (!CanRead(2)) { ok = false; return 0; }
        uint16_t val;
        std::memcpy(&val, data + pos, 2);
        pos += 2;
        return val;
    }

    uint32_t ReadU32() noexcept {
        if (!CanRead(4)) { ok = false; return 0; }
        uint32_t val;
        std::memcpy(&val, data + pos, 4);
        pos += 4;
        return val;
    }

    uint64_t ReadU64() noexcept {
        if (!CanRead(8)) { ok = false; return 0; }
        uint64_t val;
        std::memcpy(&val, data + pos, 8);
        pos += 8;
        return val;
    }

    uint32_t ReadIndex(uint8_t indexSize) noexcept {
        if (indexSize == 2) return static_cast<uint32_t>(ReadU16());
        if (indexSize == 4) return ReadU32();
        ok = false;
        return 0;
    }

    void Skip(uint32_t count) noexcept {
        if (!CanRead(count)) { ok = false; return; }
        pos += count;
    }
};

// Overflow-safe imageBase + rva
[[nodiscard]] bool SafeAddRVA(GuestAddress base, uint32_t rva, GuestAddress& out) noexcept {
    const uint64_t delta = static_cast<uint64_t>(rva);
    if (base > std::numeric_limits<GuestAddress>::max() - delta) return false;
    out = base + delta;
    return true;
}

[[nodiscard]] bool ReserveRows(auto& rows, uint32_t cap) noexcept {
    try {
        rows.reserve(cap);
        return true;
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::length_error&) {
        return false;
    }
}

// Count set bits in a 64-bit mask
[[nodiscard]] uint32_t PopCount64(uint64_t v) noexcept {
    uint32_t count = 0;
    while (v) { v &= (v - 1); ++count; }
    return count;
}

} // anonymous namespace

// ============================================================================
// Public API — Accessors
// ============================================================================

bool MetadataParser::IsValid() const noexcept { return m_valid; }

const COR20Header& MetadataParser::GetCOR20Header() const noexcept { return m_cor20; }

const MetadataRoot& MetadataParser::GetMetadataRoot() const noexcept { return m_metadataRoot; }

uint32_t MetadataParser::GetTableRowCount(MetadataTableId table) const noexcept {
    auto idx = static_cast<uint8_t>(table);
    return (idx < kMaxMetadataTables) ? m_rowCounts[idx] : 0;
}

const std::vector<TypeDefRow>& MetadataParser::GetTypeDefs() const noexcept { return m_typeDefs; }
const std::vector<MethodDefRow>& MetadataParser::GetMethodDefs() const noexcept { return m_methodDefs; }
const std::vector<MemberRefRow>& MetadataParser::GetMemberRefs() const noexcept { return m_memberRefs; }
const std::vector<TypeRefRow>& MetadataParser::GetTypeRefs() const noexcept { return m_typeRefs; }
const std::vector<AssemblyRefRow>& MetadataParser::GetAssemblyRefs() const noexcept { return m_assemblyRefs; }
std::optional<AssemblyRow> MetadataParser::GetAssembly() const noexcept { return m_assembly; }
const std::vector<ImplMapRow>& MetadataParser::GetImplMaps() const noexcept { return m_implMaps; }
const std::vector<ModuleRefRow>& MetadataParser::GetModuleRefs() const noexcept { return m_moduleRefs; }
const std::vector<FieldRVARow>& MetadataParser::GetFieldRVAs() const noexcept { return m_fieldRVAs; }

// ============================================================================
// Reset — clear all state for a fresh parse
// ============================================================================

void MetadataParser::Reset() noexcept {
    m_valid     = false;
    m_imageBase = 0;
    m_cor20     = {};
    m_metadataRoot = {};

    m_stringsHeap.clear();
    m_blobHeap.clear();
    m_guidHeap.clear();
    m_usHeap.clear();
    m_tildeData.clear();

    m_rowCounts.fill(0);
    m_tableRowSizes.fill(0);
    m_tableDataOffset = 0;

    m_stringIdxSize = 2;
    m_guidIdxSize   = 2;
    m_blobIdxSize   = 2;

    m_typeDefOrRefSize        = 2;
    m_hasConstantSize         = 2;
    m_hasCustomAttributeSize  = 2;
    m_hasFieldMarshalSize     = 2;
    m_hasDeclSecuritySize     = 2;
    m_memberRefParentSize     = 2;
    m_hasSemanticsSize        = 2;
    m_methodDefOrRefSize      = 2;
    m_memberForwardedSize     = 2;
    m_implementationSize      = 2;
    m_customAttributeTypeSize = 2;
    m_resolutionScopeSize     = 2;
    m_typeOrMethodDefSize     = 2;

    m_typeDefs.clear();
    m_methodDefs.clear();
    m_memberRefs.clear();
    m_typeRefs.clear();
    m_assemblyRefs.clear();
    m_assembly.reset();
    m_implMaps.clear();
    m_moduleRefs.clear();
    m_fieldRVAs.clear();
}

// ============================================================================
// Parse — main entry point
// ============================================================================

bool MetadataParser::Parse(VirtualMemory& memory, GuestAddress imageBase) noexcept {
    try {
        Reset();
        m_imageBase = imageBase;

        uint32_t clrRVA  = 0;
        uint32_t clrSize = 0;

        if (!ParsePEHeaders(memory, clrRVA, clrSize))  return false;
        if (!ParseCOR20(memory, clrRVA, clrSize))       return false;
        if (!ParseMetadataBlob(memory))                  return false;
        if (!ParseTildeHeader())                         return false;

        ComputeCodedIndexSizes();

        if (!ComputeTableRowSizes()) return false;
        if (!ParseAllTables())       return false;

        m_valid = true;
        return true;
    } catch (const std::bad_alloc&) {
        Reset();
        return false;
    } catch (const std::length_error&) {
        Reset();
        return false;
    }
}

// ============================================================================
// ParsePEHeaders — walk DOS → NT → DataDirectory[14]
// ============================================================================

bool MetadataParser::ParsePEHeaders(
    VirtualMemory& mem, uint32_t& clrRVA, uint32_t& clrSize) noexcept
{
    PE::DOSHeader dos{};
    if (mem.Read(m_imageBase, &dos, static_cast<uint32_t>(sizeof(dos))) != ErrorCode::Success) return false;
    if (dos.e_magic != PE::kDOSMagic) return false;
    if (dos.e_lfanew < 0 || static_cast<uint32_t>(dos.e_lfanew) > kMaxElfanew) return false;

    GuestAddress peAddr = 0;
    if (!SafeAddRVA(m_imageBase, static_cast<uint32_t>(dos.e_lfanew), peAddr)) return false;

    uint32_t peSignature = 0;
    if (mem.ReadU32(peAddr, peSignature) != ErrorCode::Success) return false;
    if (peSignature != PE::kNTSignature) return false;

    GuestAddress fileHdrAddr = peAddr + 4;
    PE::FileHeader fileHdr{};
    if (mem.Read(fileHdrAddr, &fileHdr, static_cast<uint32_t>(sizeof(fileHdr))) != ErrorCode::Success) return false;

    GuestAddress optHdrAddr = fileHdrAddr + static_cast<uint32_t>(sizeof(PE::FileHeader));

    // Read optional header magic to determine PE32 vs PE32+
    uint16_t magic = 0;
    if (mem.ReadU16(optHdrAddr, magic) != ErrorCode::Success) return false;

    PE::DataDirectory clrDir{};

    static constexpr uint32_t kMinOpt32ForCLR =
        static_cast<uint32_t>(offsetof(PE::OptionalHeader32, DataDirectories))
        + static_cast<uint32_t>(sizeof(PE::DataDirectory)) * (PE::kDirCLRRuntime + 1);
    static constexpr uint32_t kMinOpt64ForCLR =
        static_cast<uint32_t>(offsetof(PE::OptionalHeader64, DataDirectories))
        + static_cast<uint32_t>(sizeof(PE::DataDirectory)) * (PE::kDirCLRRuntime + 1);

    if (magic == PE::kPE32Magic) {
        PE::OptionalHeader32 opt{};
        uint32_t readSize = std::min(
            static_cast<uint32_t>(sizeof(opt)),
            static_cast<uint32_t>(fileHdr.SizeOfOptionalHeader));
        if (readSize < kMinOpt32ForCLR) return false;
        if (mem.Read(optHdrAddr, &opt, readSize) != ErrorCode::Success) return false;
        if (opt.NumberOfRvaAndSizes <= PE::kDirCLRRuntime) return false;
        clrDir = opt.DataDirectories[PE::kDirCLRRuntime];
    } else if (magic == PE::kPE64Magic) {
        PE::OptionalHeader64 opt{};
        uint32_t readSize = std::min(
            static_cast<uint32_t>(sizeof(opt)),
            static_cast<uint32_t>(fileHdr.SizeOfOptionalHeader));
        if (readSize < kMinOpt64ForCLR) return false;
        if (mem.Read(optHdrAddr, &opt, readSize) != ErrorCode::Success) return false;
        if (opt.NumberOfRvaAndSizes <= PE::kDirCLRRuntime) return false;
        clrDir = opt.DataDirectories[PE::kDirCLRRuntime];
    } else {
        return false;
    }

    if (clrDir.VirtualAddress == 0 || clrDir.Size < static_cast<uint32_t>(sizeof(COR20Header))) return false;

    clrRVA  = clrDir.VirtualAddress;
    clrSize = clrDir.Size;
    return true;
}

// ============================================================================
// ParseCOR20 — read IMAGE_COR20_HEADER from guest memory
// ============================================================================

bool MetadataParser::ParseCOR20(
    VirtualMemory& mem, uint32_t clrRVA, uint32_t clrSize) noexcept
{
    GuestAddress cor20Addr = 0;
    if (!SafeAddRVA(m_imageBase, clrRVA, cor20Addr)) return false;

    static_assert(sizeof(COR20Header) == 72, "COR20Header must be 72 bytes");

    if (clrSize < static_cast<uint32_t>(sizeof(COR20Header))) return false;

    if (mem.Read(cor20Addr, &m_cor20, static_cast<uint32_t>(sizeof(COR20Header))) != ErrorCode::Success) return false;

    if (m_cor20.cb < 72) return false;
    if (m_cor20.metadataRVA == 0 || m_cor20.metadataSize == 0) return false;
    if (m_cor20.metadataSize > kMaxMetadataSize) return false;

    return true;
}

// ============================================================================
// ParseMetadataBlob — read entire metadata region and extract streams
// ============================================================================

bool MetadataParser::ParseMetadataBlob(VirtualMemory& mem) {
    GuestAddress metaAddr = 0;
    if (!SafeAddRVA(m_imageBase, m_cor20.metadataRVA, metaAddr)) return false;

    uint32_t metaSize = m_cor20.metadataSize;
    if (metaSize > kMaxMetadataSize) return false;

    // Read entire metadata region into host memory
    std::vector<uint8_t> metaBlob(metaSize);

    if (mem.Read(metaAddr, metaBlob.data(), metaSize) != ErrorCode::Success) return false;

    BufferCursor cur(metaBlob.data(), metaSize);

    // --- Metadata Root Header (ECMA-335 §II.24.2.1) ---
    uint32_t sig = cur.ReadU32();
    if (sig != kMetadataSignature) return false;

    m_metadataRoot.signature    = sig;
    m_metadataRoot.majorVersion = cur.ReadU16();
    m_metadataRoot.minorVersion = cur.ReadU16();
    m_metadataRoot.reserved     = cur.ReadU32();
    m_metadataRoot.versionLength = cur.ReadU32();
    if (!cur.ok) return false;

    if (m_metadataRoot.versionLength > kMaxVersionLength) return false;
    if (!cur.CanRead(m_metadataRoot.versionLength)) return false;

    // Extract null-terminated version string
    const auto* verBytes = reinterpret_cast<const char*>(cur.data + cur.pos);
    uint32_t verLen = 0;
    while (verLen < m_metadataRoot.versionLength && verBytes[verLen] != '\0') ++verLen;
    m_metadataRoot.versionString.assign(verBytes, verLen);
    cur.Skip(m_metadataRoot.versionLength);

    m_metadataRoot.flags       = cur.ReadU16();
    m_metadataRoot.streamCount = cur.ReadU16();
    if (!cur.ok) return false;
    if (m_metadataRoot.streamCount > kMaxStreamCount) return false;

    // --- Parse Stream Headers (ECMA-335 §II.24.2.2) ---
    struct StreamInfo {
        uint32_t    offset;
        uint32_t    size;
        std::string name;
    };
    std::vector<StreamInfo> streams;
    if (!ReserveRows(streams, m_metadataRoot.streamCount)) return false;

    for (uint16_t i = 0; i < m_metadataRoot.streamCount; ++i) {
        StreamInfo si{};
        si.offset = cur.ReadU32();
        si.size   = cur.ReadU32();
        if (!cur.ok) return false;

        // Read null-terminated stream name (padded to 4-byte boundary)
        if (cur.pos >= cur.size) return false;
        const auto* nameStart = reinterpret_cast<const char*>(cur.data + cur.pos);
        uint32_t nameRemaining = cur.size - cur.pos;
        uint32_t nameLen = 0;
        bool foundTerminator = false;
        while (nameLen < nameRemaining && nameLen < kMaxStreamNameLength) {
            if (nameStart[nameLen] == '\0') {
                foundTerminator = true;
                break;
            }
            ++nameLen;
        }
        if (!foundTerminator) return false;
        si.name.assign(nameStart, nameLen);

        // Advance past name + null + padding to 4-byte boundary
        uint32_t paddedLen = ((nameLen + 1) + 3) & ~3u;
        cur.Skip(paddedLen);
        if (!cur.ok) return false;

        // Validate stream bounds within metadata blob
        if (si.offset > metaSize) return false;
        if (si.size > (metaSize - si.offset)) return false;
        if (si.size > kMaxStreamSize) return false;

        streams.push_back(std::move(si));
    }

    // --- Extract each stream into its host-side buffer ---
    for (const auto& si : streams) {
        const uint8_t* streamData = metaBlob.data() + si.offset;

        if (si.name == "#~" || si.name == "#-") {
            m_tildeData.assign(streamData, streamData + si.size);
        } else if (si.name == "#Strings") {
            m_stringsHeap.assign(streamData, streamData + si.size);
        } else if (si.name == "#Blob") {
            m_blobHeap.assign(streamData, streamData + si.size);
        } else if (si.name == "#GUID") {
            m_guidHeap.assign(streamData, streamData + si.size);
        } else if (si.name == "#US") {
            m_usHeap.assign(streamData, streamData + si.size);
        }
        // Unknown streams are silently ignored (forward compatibility)
    }

    // The #~ (or #-) stream is mandatory
    if (m_tildeData.empty()) return false;

    return true;
}

// ============================================================================
// ParseTildeHeader — parse #~ stream header, extract row counts
// ============================================================================

bool MetadataParser::ParseTildeHeader() noexcept {
    BufferCursor cur(m_tildeData.data(), static_cast<uint32_t>(m_tildeData.size()));

    // #~ stream header (ECMA-335 §II.24.2.6)
    uint32_t reserved    = cur.ReadU32();
    uint8_t  majorVer    = cur.ReadU8();
    uint8_t  minorVer    = cur.ReadU8();
    uint8_t  heapSizes   = cur.ReadU8();
    /*reserved2*/          cur.ReadU8();
    uint64_t validMask   = cur.ReadU64();
    uint64_t sortedMask  = cur.ReadU64();
    if (!cur.ok) return false;

    (void)reserved;
    (void)majorVer;
    (void)minorVer;
    (void)sortedMask;

    // Decode heap index sizes from HeapSizes byte
    m_stringIdxSize = (heapSizes & 0x01) ? 4 : 2;
    m_guidIdxSize   = (heapSizes & 0x02) ? 4 : 2;
    m_blobIdxSize   = (heapSizes & 0x04) ? 4 : 2;

    // Count the number of tables present
    uint32_t tableCount = PopCount64(validMask);
    if (!cur.CanRead(tableCount * 4)) return false;

    // Read row counts for each table that has its bit set
    uint32_t tableIdx = 0;
    for (uint8_t i = 0; i < 64 && i < kMaxMetadataTables; ++i) {
        if (validMask & (1ULL << i)) {
            uint32_t rows = cur.ReadU32();
            if (!cur.ok) return false;
            if (rows > kMaxRowsPerTable) return false;
            m_rowCounts[i] = rows;
            ++tableIdx;
        }
    }
    // Bits beyond kMaxMetadataTables in validMask indicate unknown tables — reject
    if (validMask >> kMaxMetadataTables) return false;

    m_tableDataOffset = cur.pos;
    return true;
}

// ============================================================================
// Index Size Computation
// ============================================================================

uint8_t MetadataParser::SimpleIdxSize(MetadataTableId table) const noexcept {
    auto idx = static_cast<uint8_t>(table);
    if (idx >= kMaxMetadataTables) return 2;
    return (m_rowCounts[idx] > 0xFFFF) ? 4 : 2;
}

uint8_t MetadataParser::CodedIdxSize(
    const MetadataTableId* tables, uint8_t tableCount, uint8_t tagBits) const noexcept
{
    uint32_t maxRows = 0;
    if (tables == nullptr || tableCount == 0 || tagBits >= 16) return 4;
    for (uint8_t i = 0; i < tableCount; ++i) {
        auto tid = static_cast<uint8_t>(tables[i]);
        if (tid < kMaxMetadataTables)
            maxRows = std::max(maxRows, m_rowCounts[tid]);
    }
    uint32_t maxFit = 1u << (16u - tagBits);
    return (maxRows < maxFit) ? 2 : 4;
}

void MetadataParser::ComputeCodedIndexSizes() noexcept {
    m_typeDefOrRefSize        = CodedIdxSize(kTypeDefOrRef,        3,  kTypeDefOrRefBits);
    m_hasConstantSize         = CodedIdxSize(kHasConstant,         3,  kHasConstantBits);
    m_hasCustomAttributeSize  = CodedIdxSize(kHasCustomAttribute,  22, kHasCustomAttributeBits);
    m_hasFieldMarshalSize     = CodedIdxSize(kHasFieldMarshal,     2,  kHasFieldMarshalBits);
    m_hasDeclSecuritySize     = CodedIdxSize(kHasDeclSecurity,     3,  kHasDeclSecurityBits);
    m_memberRefParentSize     = CodedIdxSize(kMemberRefParent,     5,  kMemberRefParentBits);
    m_hasSemanticsSize        = CodedIdxSize(kHasSemantics,        2,  kHasSemanticsBits);
    m_methodDefOrRefSize      = CodedIdxSize(kMethodDefOrRef,      2,  kMethodDefOrRefBits);
    m_memberForwardedSize     = CodedIdxSize(kMemberForwarded,     2,  kMemberForwardedBits);
    m_implementationSize      = CodedIdxSize(kImplementation,      3,  kImplementationBits);
    m_customAttributeTypeSize = CodedIdxSize(kCustomAttributeType, 2,  kCustomAttributeTypeBits);
    m_resolutionScopeSize     = CodedIdxSize(kResolutionScope,     4,  kResolutionScopeBits);
    m_typeOrMethodDefSize     = CodedIdxSize(kTypeOrMethodDef,     2,  kTypeOrMethodDefBits);
}

// ============================================================================
// ComputeRowSize — ECMA-335 §II.22 table schemas
// ============================================================================

uint32_t MetadataParser::ComputeRowSize(uint8_t tableId) const noexcept {
    using T = MetadataTableId;
    auto S  = m_stringIdxSize;
    auto G  = m_guidIdxSize;
    auto B  = m_blobIdxSize;
    auto SI = [this](T t) -> uint8_t { return SimpleIdxSize(t); };

    switch (static_cast<T>(tableId)) {
    case T::Module:              return 2 + S + G + G + G;
    case T::TypeRef:             return m_resolutionScopeSize + S + S;
    case T::TypeDef:             return 4 + S + S + m_typeDefOrRefSize + SI(T::Field) + SI(T::MethodDef);
    case T::FieldPtr:            return SI(T::Field);
    case T::Field:               return 2 + S + B;
    case T::MethodPtr:           return SI(T::MethodDef);
    case T::MethodDef:           return 4 + 2 + 2 + S + B + SI(T::Param);
    case T::ParamPtr:            return SI(T::Param);
    case T::Param:               return 2 + 2 + S;
    case T::InterfaceImpl:       return SI(T::TypeDef) + m_typeDefOrRefSize;
    case T::MemberRef:           return m_memberRefParentSize + S + B;
    case T::Constant:            return 2 + m_hasConstantSize + B;
    case T::CustomAttribute:     return m_hasCustomAttributeSize + m_customAttributeTypeSize + B;
    case T::FieldMarshal:        return m_hasFieldMarshalSize + B;
    case T::DeclSecurity:        return 2 + m_hasDeclSecuritySize + B;
    case T::ClassLayout:         return 2 + 4 + SI(T::TypeDef);
    case T::FieldLayout:         return 4 + SI(T::Field);
    case T::StandAloneSig:       return B;
    case T::EventMap:            return SI(T::TypeDef) + SI(T::Event);
    case T::EventPtr:            return SI(T::Event);
    case T::Event:               return 2 + S + m_typeDefOrRefSize;
    case T::PropertyMap:         return SI(T::TypeDef) + SI(T::Property);
    case T::PropertyPtr:         return SI(T::Property);
    case T::Property:            return 2 + S + B;
    case T::MethodSemantics:     return 2 + SI(T::MethodDef) + m_hasSemanticsSize;
    case T::MethodImpl:          return SI(T::TypeDef) + m_methodDefOrRefSize + m_methodDefOrRefSize;
    case T::ModuleRef:           return S;
    case T::TypeSpec:            return B;
    case T::ImplMap:             return 2 + m_memberForwardedSize + S + SI(T::ModuleRef);
    case T::FieldRVA:            return 4 + SI(T::Field);
    case T::EncLog:              return 4 + 4;
    case T::EncMap:              return 4;
    case T::Assembly:            return 4 + 2 + 2 + 2 + 2 + 4 + B + S + S;
    case T::AssemblyProcessor:   return 4;
    case T::AssemblyOS:          return 4 + 4 + 4;
    case T::AssemblyRef:         return 2 + 2 + 2 + 2 + 4 + B + S + S + B;
    case T::AssemblyRefProcessor:return 4 + SI(T::AssemblyRef);
    case T::AssemblyRefOS:       return 4 + 4 + 4 + SI(T::AssemblyRef);
    case T::File:                return 4 + S + B;
    case T::ExportedType:        return 4 + 4 + S + S + m_implementationSize;
    case T::ManifestResource:    return 4 + 4 + S + m_implementationSize;
    case T::NestedClass:         return SI(T::TypeDef) + SI(T::TypeDef);
    case T::GenericParam:        return 2 + 2 + m_typeOrMethodDefSize + S;
    case T::MethodSpec:          return m_methodDefOrRefSize + B;
    case T::GenericParamConstraint: return SI(T::GenericParam) + m_typeDefOrRefSize;
    default:                     return 0;
    }
}

bool MetadataParser::ComputeTableRowSizes() noexcept {
    for (uint8_t i = 0; i < kMaxMetadataTables; ++i) {
        if (m_rowCounts[i] == 0) continue;
        uint32_t rowSize = ComputeRowSize(i);
        if (rowSize == 0) return false; // Unknown table with rows — corrupt
        m_tableRowSizes[i] = rowSize;
    }

    // Verify total table data fits within the #~ stream
    uint64_t totalBytes = 0;
    for (uint8_t i = 0; i < kMaxMetadataTables; ++i) {
        totalBytes += static_cast<uint64_t>(m_rowCounts[i]) * m_tableRowSizes[i];
    }
    if (m_tableDataOffset > m_tildeData.size()) return false;
    uint64_t available = m_tildeData.size() - m_tableDataOffset;
    if (totalBytes > available) return false;

    return true;
}

// ============================================================================
// ParseAllTables — walk all table rows, extracting the ones we need
// ============================================================================

bool MetadataParser::ParseAllTables() {
    BufferCursor cur(
        m_tildeData.data(),
        static_cast<uint32_t>(m_tildeData.size()),
        m_tableDataOffset);

    using T = MetadataTableId;
    auto S  = m_stringIdxSize;
    auto B  = m_blobIdxSize;

    for (uint8_t tableId = 0; tableId < kMaxMetadataTables; ++tableId) {
        uint32_t rows    = m_rowCounts[tableId];
        uint32_t rowSize = m_tableRowSizes[tableId];
        if (rows == 0) continue;

        switch (static_cast<T>(tableId)) {

        // ================================================================
        // TypeRef (0x01)
        // ================================================================
        case T::TypeRef: {
            uint32_t cap = std::min(rows, kMaxParsedTypes);
            if (!ReserveRows(m_typeRefs, cap)) return false;
            for (uint32_t r = 0; r < rows; ++r) {
                TypeRefRow row{};
                row.resolutionScope = cur.ReadIndex(m_resolutionScopeSize);
                row.typeName        = ReadStringHeap(cur.ReadIndex(S));
                row.typeNamespace   = ReadStringHeap(cur.ReadIndex(S));
                if (!cur.ok) return false;
                if (r < cap) m_typeRefs.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // TypeDef (0x02)
        // ================================================================
        case T::TypeDef: {
            uint32_t cap = std::min(rows, kMaxParsedTypes);
            if (!ReserveRows(m_typeDefs, cap)) return false;
            uint8_t fieldIdxSz  = SimpleIdxSize(T::Field);
            uint8_t methodIdxSz = SimpleIdxSize(T::MethodDef);
            for (uint32_t r = 0; r < rows; ++r) {
                TypeDefRow row{};
                row.flags            = cur.ReadU32();
                row.typeName         = ReadStringHeap(cur.ReadIndex(S));
                row.typeNamespace    = ReadStringHeap(cur.ReadIndex(S));
                row.extendsCodedIndex = cur.ReadIndex(m_typeDefOrRefSize);
                row.fieldList        = cur.ReadIndex(fieldIdxSz);
                row.methodList       = cur.ReadIndex(methodIdxSz);
                if (!cur.ok) return false;
                if (r < cap) m_typeDefs.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // MethodDef (0x06)
        // ================================================================
        case T::MethodDef: {
            uint32_t cap = std::min(rows, kMaxParsedMethods);
            if (!ReserveRows(m_methodDefs, cap)) return false;
            uint8_t paramIdxSz = SimpleIdxSize(T::Param);
            for (uint32_t r = 0; r < rows; ++r) {
                MethodDefRow row{};
                row.rva            = cur.ReadU32();
                row.implFlags      = cur.ReadU16();
                row.flags          = cur.ReadU16();
                row.name           = ReadStringHeap(cur.ReadIndex(S));
                row.signatureIndex = cur.ReadIndex(B);
                row.paramList      = cur.ReadIndex(paramIdxSz);
                if (!cur.ok) return false;
                if (r < cap) m_methodDefs.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // MemberRef (0x0A)
        // ================================================================
        case T::MemberRef: {
            uint32_t cap = std::min(rows, kMaxMemberRefs);
            if (!ReserveRows(m_memberRefs, cap)) return false;
            for (uint32_t r = 0; r < rows; ++r) {
                MemberRefRow row{};
                row.classCodedIndex = cur.ReadIndex(m_memberRefParentSize);
                row.name            = ReadStringHeap(cur.ReadIndex(S));
                row.signatureIndex  = cur.ReadIndex(B);
                if (!cur.ok) return false;
                if (r < cap) m_memberRefs.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // ModuleRef (0x1A)
        // ================================================================
        case T::ModuleRef: {
            uint32_t cap = std::min(rows, kMaxModuleRefs);
            if (!ReserveRows(m_moduleRefs, cap)) return false;
            for (uint32_t r = 0; r < rows; ++r) {
                ModuleRefRow row{};
                row.name = ReadStringHeap(cur.ReadIndex(S));
                if (!cur.ok) return false;
                if (r < cap) m_moduleRefs.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // ImplMap (0x1C)
        // ================================================================
        case T::ImplMap: {
            uint32_t cap = std::min(rows, kMaxImplMaps);
            if (!ReserveRows(m_implMaps, cap)) return false;
            uint8_t modRefSz = SimpleIdxSize(T::ModuleRef);
            for (uint32_t r = 0; r < rows; ++r) {
                ImplMapRow row{};
                row.mappingFlags         = cur.ReadU16();
                row.memberForwardedIndex = cur.ReadIndex(m_memberForwardedSize);
                row.importName           = ReadStringHeap(cur.ReadIndex(S));
                row.importScopeIndex     = cur.ReadIndex(modRefSz);
                if (!cur.ok) return false;
                if (r < cap) m_implMaps.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // FieldRVA (0x1D)
        // ================================================================
        case T::FieldRVA: {
            uint32_t cap = std::min(rows, kMaxFieldRVAs);
            if (!ReserveRows(m_fieldRVAs, cap)) return false;
            uint8_t fieldSz = SimpleIdxSize(T::Field);
            for (uint32_t r = 0; r < rows; ++r) {
                FieldRVARow row{};
                row.rva        = cur.ReadU32();
                row.fieldIndex = cur.ReadIndex(fieldSz);
                if (!cur.ok) return false;
                if (r < cap) m_fieldRVAs.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // Assembly (0x20) — at most 1 row
        // ================================================================
        case T::Assembly: {
            if (rows > 1) return false; // ECMA-335 mandates at most 1
            AssemblyRow row{};
            row.hashAlgId      = cur.ReadU32();
            row.majorVersion   = cur.ReadU16();
            row.minorVersion   = cur.ReadU16();
            row.buildNumber    = cur.ReadU16();
            row.revisionNumber = cur.ReadU16();
            row.flags          = cur.ReadU32();
            row.publicKeyIndex = cur.ReadIndex(B);
            row.name           = ReadStringHeap(cur.ReadIndex(S));
            row.culture        = ReadStringHeap(cur.ReadIndex(S));
            if (!cur.ok) return false;
            m_assembly = std::move(row);
            break;
        }

        // ================================================================
        // AssemblyRef (0x23)
        // ================================================================
        case T::AssemblyRef: {
            uint32_t cap = std::min(rows, kMaxAssemblyRefs);
            if (!ReserveRows(m_assemblyRefs, cap)) return false;
            for (uint32_t r = 0; r < rows; ++r) {
                AssemblyRefRow row{};
                row.majorVersion       = cur.ReadU16();
                row.minorVersion       = cur.ReadU16();
                row.buildNumber        = cur.ReadU16();
                row.revisionNumber     = cur.ReadU16();
                row.flags              = cur.ReadU32();
                row.publicKeyOrTokenIndex = cur.ReadIndex(B);
                row.name               = ReadStringHeap(cur.ReadIndex(S));
                row.culture            = ReadStringHeap(cur.ReadIndex(S));
                row.hashValueIndex     = cur.ReadIndex(B);
                if (!cur.ok) return false;
                if (r < cap) m_assemblyRefs.push_back(std::move(row));
            }
            break;
        }

        // ================================================================
        // All other tables — skip by advancing the cursor
        // ================================================================
        default: {
            uint64_t skipBytes = static_cast<uint64_t>(rows) * rowSize;
            if (skipBytes > std::numeric_limits<uint32_t>::max()) return false;
            if (!cur.CanRead(static_cast<uint32_t>(skipBytes))) return false;
            cur.Skip(static_cast<uint32_t>(skipBytes));
            break;
        }

        } // switch
    }

    return cur.ok;
}

// ============================================================================
// Heap Access
// ============================================================================

std::string MetadataParser::ReadStringHeap(uint32_t offset) const {
    if (offset == 0) return {};
    if (offset >= m_stringsHeap.size()) return {};

    const auto* start = reinterpret_cast<const char*>(m_stringsHeap.data() + offset);
    uint32_t maxLen   = static_cast<uint32_t>(m_stringsHeap.size()) - offset;
    uint32_t len = 0;
    while (len < maxLen && len < kMaxStringReadLength && start[len] != '\0') ++len;
    return std::string(start, len);
}

std::string MetadataParser::ReadString(uint32_t heapOffset) const noexcept {
    try {
        return ReadStringHeap(heapOffset);
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

uint32_t MetadataParser::DecodeBlobLength(
    const uint8_t* ptr, uint32_t remaining, uint32_t& headerSize) const noexcept
{
    headerSize = 0;
    if (remaining < 1) return 0;

    if ((ptr[0] & 0x80) == 0) {
        headerSize = 1;
        return ptr[0];
    }
    if ((ptr[0] & 0xC0) == 0x80) {
        if (remaining < 2) return 0;
        headerSize = 2;
        return (static_cast<uint32_t>(ptr[0] & 0x3F) << 8) | ptr[1];
    }
    if ((ptr[0] & 0xE0) == 0xC0) {
        if (remaining < 4) return 0;
        headerSize = 4;
        return (static_cast<uint32_t>(ptr[0] & 0x1F) << 24) |
               (static_cast<uint32_t>(ptr[1]) << 16) |
               (static_cast<uint32_t>(ptr[2]) << 8) |
                static_cast<uint32_t>(ptr[3]);
    }
    return 0; // Invalid encoding
}

std::u16string MetadataParser::ReadUserString(uint32_t heapOffset) const noexcept {
    try {
        if (heapOffset == 0 || heapOffset >= m_usHeap.size()) return {};

        const uint8_t* ptr = m_usHeap.data() + heapOffset;
        uint32_t remaining = static_cast<uint32_t>(m_usHeap.size()) - heapOffset;

        uint32_t headerSize = 0;
        uint32_t length = DecodeBlobLength(ptr, remaining, headerSize);
        if (headerSize == 0 || length == 0) return {};
        if (length > remaining - headerSize) return {};
        if (length > kMaxUserStringReadLen) return {};

        // The blob contains UTF-16LE chars followed by a 1-byte terminal flag.
        const uint8_t* strData = ptr + headerSize;
        uint32_t charBytes = (length >= 1) ? (length - 1) : 0;
        if ((charBytes % 2u) != 0) return {};
        uint32_t charCount = charBytes / 2;
        if (charCount == 0) return {};

        std::u16string result(charCount, u'\0');
        std::memcpy(result.data(), strData, charCount * 2);
        return result;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

std::vector<uint8_t> MetadataParser::ReadBlob(uint32_t heapOffset) const noexcept {
    try {
        if (heapOffset >= m_blobHeap.size()) return {};

        const uint8_t* ptr = m_blobHeap.data() + heapOffset;
        uint32_t remaining = static_cast<uint32_t>(m_blobHeap.size()) - heapOffset;

        uint32_t headerSize = 0;
        uint32_t length = DecodeBlobLength(ptr, remaining, headerSize);
        if (headerSize == 0) return {};
        if (length == 0) return {};
        if (length > remaining - headerSize) return {};
        if (length > kMaxBlobReadLength) return {};

        return std::vector<uint8_t>(ptr + headerSize, ptr + headerSize + length);
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

// ============================================================================
// ResolveToken — metadata token → human-readable name
// ============================================================================

std::string MetadataParser::ResolveToken(MetadataToken token) const noexcept {
    try {
    if (!m_valid || token.IsNull()) return {};

    uint32_t row = token.Row();
    if (row == 0) return {};
    uint32_t index = row - 1; // Tokens are 1-based

    switch (token.Table()) {
    case MetadataTableId::TypeDef: {
        if (index >= m_typeDefs.size()) return {};
        const auto& td = m_typeDefs[index];
        if (td.typeNamespace.empty()) return td.typeName;
        return td.typeNamespace + "." + td.typeName;
    }
    case MetadataTableId::TypeRef: {
        if (index >= m_typeRefs.size()) return {};
        const auto& tr = m_typeRefs[index];
        if (tr.typeNamespace.empty()) return tr.typeName;
        return tr.typeNamespace + "." + tr.typeName;
    }
    case MetadataTableId::MethodDef: {
        if (index >= m_methodDefs.size()) return {};
        const auto& md = m_methodDefs[index];

        // Walk TypeDef table to find the owning type
        std::string owner;
        for (size_t i = 0; i < m_typeDefs.size(); ++i) {
            uint32_t methodStart = m_typeDefs[i].methodList;
            uint32_t methodEnd   = (i + 1 < m_typeDefs.size())
                ? m_typeDefs[i + 1].methodList
                : static_cast<uint32_t>(m_methodDefs.size() + 1);
            if (row >= methodStart && row < methodEnd) {
                if (!m_typeDefs[i].typeNamespace.empty())
                    owner = m_typeDefs[i].typeNamespace + ".";
                owner += m_typeDefs[i].typeName;
                break;
            }
        }
        if (owner.empty()) return md.name;
        return owner + "::" + md.name;
    }
    case MetadataTableId::MemberRef: {
        if (index >= m_memberRefs.size()) return {};
        const auto& mr = m_memberRefs[index];

        // Decode MemberRefParent coded index (3 tag bits)
        uint32_t tag       = mr.classCodedIndex & 0x07;
        uint32_t parentRow = mr.classCodedIndex >> 3;
        std::string parent;

        if (parentRow > 0) {
            uint32_t pi = parentRow - 1;
            if (tag == 0 && pi < m_typeDefs.size()) {
                const auto& td = m_typeDefs[pi];
                if (!td.typeNamespace.empty()) parent = td.typeNamespace + ".";
                parent += td.typeName;
            } else if (tag == 1 && pi < m_typeRefs.size()) {
                const auto& tr = m_typeRefs[pi];
                if (!tr.typeNamespace.empty()) parent = tr.typeNamespace + ".";
                parent += tr.typeName;
            }
        }
        if (parent.empty()) return mr.name;
        return parent + "::" + mr.name;
    }
    case MetadataTableId::AssemblyRef: {
        if (index >= m_assemblyRefs.size()) return {};
        return m_assemblyRefs[index].name;
    }
    case MetadataTableId::Assembly: {
        if (m_assembly.has_value()) return m_assembly->name;
        return {};
    }
    case MetadataTableId::ModuleRef: {
        if (index >= m_moduleRefs.size()) return {};
        return m_moduleRefs[index].name;
    }
    default:
        return {};
    }
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

// ============================================================================
// GetMethodBodyAddress — resolve MethodDef RVA to guest address
// ============================================================================

std::optional<GuestAddress> MetadataParser::GetMethodBodyAddress(uint32_t methodIndex) const noexcept {
    if (!m_valid || methodIndex >= m_methodDefs.size()) return std::nullopt;

    uint32_t rva = m_methodDefs[methodIndex].rva;
    if (rva == 0) return std::nullopt; // Abstract / runtime / extern

    GuestAddress addr = 0;
    if (!SafeAddRVA(m_imageBase, rva, addr)) return std::nullopt;
    return addr;
}

// ============================================================================
// GetAllUserStrings — enumerate the #US heap
// ============================================================================

std::vector<std::u16string> MetadataParser::GetAllUserStrings() const noexcept {
    try {
    std::vector<std::u16string> result;
    if (m_usHeap.size() <= 1) return result;
    if (!ReserveRows(result, kMaxExtractedStrings)) return result;

    // #US heap starts with a 0x00 byte (empty entry), iterate from offset 1
    uint32_t offset = 1;
    while (offset < m_usHeap.size()) {
        if (result.size() >= kMaxParsedStrings) break;

        const uint8_t* ptr = m_usHeap.data() + offset;
        uint32_t remaining = static_cast<uint32_t>(m_usHeap.size()) - offset;

        uint32_t headerSize = 0;
        uint32_t length = DecodeBlobLength(ptr, remaining, headerSize);
        if (headerSize == 0) break;

        // Extract this user string if non-empty
        if (length > remaining - headerSize) break;

        if (length > 0) {
            auto str = ReadUserString(offset);
            if (!str.empty())
                result.push_back(std::move(str));
        }

        // Advance to next entry
        uint32_t entrySize = headerSize + length;
        if (entrySize == 0) break;
        offset += entrySize;
    }

    return result;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

} // namespace Phantom::CLR
