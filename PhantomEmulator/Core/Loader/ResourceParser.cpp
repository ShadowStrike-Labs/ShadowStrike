/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ResourceParser.cpp — PE resource directory tree parser
 *
 * Recursively walks the three-level PE resource directory tree:
 *   Level 0: Resource Type   (RT_ICON, RT_RCDATA, RT_MANIFEST, ...)
 *   Level 1: Resource Name   (integer ID or named string)
 *   Level 2: Language         (LCID)
 *   Leaf:    ResourceDataEntry (RVA + size of actual data)
 *
 * Anti-evasion hardening:
 *   - Recursion depth capped at PE::kMaxResourceDepth
 *   - Total entry count capped at PE::kMaxResourceEntries
 *   - All file offsets validated against buffer bounds
 *   - String lengths capped at 256 characters
 *   - No heap allocation in hot validation paths
 *
 * Shannon entropy calculation enables detection of encrypted/packed resource
 * blobs — a critical signal for identifying embedded malware payloads hidden
 * inside benign-looking PE resources.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ResourceParser.hpp"

#include <cmath>
#include <cstring>
#include <algorithm>
#include <limits>
#include <new>

namespace Phantom {

// ============================================================================
// Internal constants
// ============================================================================

// Maximum characters in a resource name string (PE spec allows 65535, we cap)
static constexpr uint32_t kMaxResourceNameChars = 256;

// Bit 31 flag in ResourceDirectoryEntry fields
static constexpr uint32_t kNameIsStringBit    = 0x80000000;
static constexpr uint32_t kOffsetIsSubdirBit  = 0x80000000;
static constexpr uint32_t kOffsetMask         = 0x7FFFFFFF;

// ============================================================================
// Helpers — safe structure reads from file buffer
// ============================================================================

namespace {

template <typename T>
[[nodiscard]] bool SafeRead(ByteSpan data, uint32_t offset, T& out) noexcept
{
    static_assert(std::is_trivially_copyable_v<T>);
    if (offset > data.size() || (data.size() - offset) < sizeof(T)) {
        return false;
    }
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

[[nodiscard]] bool IsOffsetValid(ByteSpan data, uint32_t offset, uint32_t size) noexcept
{
    if (size == 0) return true;
    return offset < data.size() && (data.size() - offset) >= size;
}

[[nodiscard]] bool AddU32(uint32_t base, uint32_t offset, uint32_t& out) noexcept
{
    if (offset > (std::numeric_limits<uint32_t>::max)() - base) {
        return false;
    }
    out = base + offset;
    return true;
}

[[nodiscard]] bool IsWithinResourceBounds(
    ByteSpan data,
    uint32_t offset,
    uint32_t size,
    uint32_t resourceBaseFileOffset,
    uint32_t resourceEndFileOffset) noexcept
{
    if (offset < resourceBaseFileOffset || offset > resourceEndFileOffset) {
        return false;
    }
    if (size > resourceEndFileOffset - offset) {
        return false;
    }
    return IsOffsetValid(data, offset, size);
}

} // anonymous namespace

// ============================================================================
// Parse — Entry point
// ============================================================================

std::vector<ResourceEntry> ResourceParser::Parse(
    ByteSpan data,
    uint32_t resourceDirRVA,
    uint32_t resourceDirSize,
    uint32_t resourceDirFileOffset) noexcept
{
    std::vector<ResourceEntry> result;

    // Validate parameters
    if (data.empty() || data.size() > (std::numeric_limits<uint32_t>::max)() ||
        resourceDirRVA == 0 || resourceDirSize == 0) {
        return result;
    }

    if (resourceDirFileOffset == 0) {
        return result;
    }

    // Ensure the resource directory fits within the file
    if (!IsOffsetValid(data, resourceDirFileOffset,
                       static_cast<uint32_t>(sizeof(PE::ResourceDirectory))))
    {
        return result;
    }

    try {
        result.reserve(64); // Pre-allocate for typical resource count
    } catch (const std::bad_alloc&) {
        return result;
    }

    uint32_t resourceEndFileOffset = 0;
    if (!AddU32(resourceDirFileOffset, resourceDirSize, resourceEndFileOffset) ||
        resourceEndFileOffset > data.size()) {
        resourceEndFileOffset = static_cast<uint32_t>(data.size());
    }

    uint32_t entryCount = 0;
    ParseDirectory(
        data,
        resourceDirFileOffset,
        resourceDirFileOffset,
        resourceEndFileOffset,
        resourceDirRVA,
        0,     // depth = 0 (type level)
        0,     // typeId not yet known
        0,     // nameId not yet known
        result,
        entryCount);

    return result;
}

// ============================================================================
// ParseDirectory — Recursive tree walk
// ============================================================================

void ResourceParser::ParseDirectory(
    ByteSpan   data,
    uint32_t   dirFileOffset,
    uint32_t   resourceBaseFileOffset,
    uint32_t   resourceEndFileOffset,
    uint32_t   resourceBaseRVA,
    uint32_t   depth,
    uint32_t   typeId,
    uint32_t   nameId,
    std::vector<ResourceEntry>& out,
    uint32_t&  entryCount) noexcept
{
    // Safety: cap recursion depth
    if (depth >= PE::kMaxResourceDepth) {
        return;
    }

    // Safety: cap total entries
    if (entryCount >= PE::kMaxResourceEntries) {
        return;
    }

    // Read the ResourceDirectory header
    PE::ResourceDirectory dir{};
    if (!IsWithinResourceBounds(data, dirFileOffset, sizeof(PE::ResourceDirectory),
                                resourceBaseFileOffset, resourceEndFileOffset) ||
        !SafeRead(data, dirFileOffset, dir)) {
        return;
    }

    const uint32_t totalEntries =
        static_cast<uint32_t>(dir.NumberOfNamedEntries) +
        static_cast<uint32_t>(dir.NumberOfIdEntries);

    // Sanity cap on entries per directory
    const uint32_t maxEntries = (totalEntries < PE::kMaxResourceEntries)
        ? totalEntries
        : PE::kMaxResourceEntries;

    // File offset of the first entry (immediately after the directory header)
    uint32_t entriesOffset = 0;
    if (!AddU32(dirFileOffset, static_cast<uint32_t>(sizeof(PE::ResourceDirectory)), entriesOffset)) {
        return;
    }

    // Validate that all entries fit in the buffer
    const uint32_t entriesSize =
        maxEntries * static_cast<uint32_t>(sizeof(PE::ResourceDirectoryEntry));
    if (!IsWithinResourceBounds(data, entriesOffset, entriesSize,
                                resourceBaseFileOffset, resourceEndFileOffset)) {
        return;
    }

    for (uint32_t i = 0; i < maxEntries; ++i) {
        if (entryCount >= PE::kMaxResourceEntries) {
            return;
        }

        PE::ResourceDirectoryEntry entry{};
        uint32_t entryOffset = 0;
        if (!AddU32(entriesOffset, i * static_cast<uint32_t>(sizeof(PE::ResourceDirectoryEntry)), entryOffset)) {
            return;
        }

        if (!SafeRead(data, entryOffset, entry)) {
            return;
        }

        // ---------------------------------------------------------------------
        // Determine the ID or name for this entry at the current depth
        // ---------------------------------------------------------------------
        uint32_t currentId  = entry.NameOrId & kOffsetMask;
        bool isNamed        = (entry.NameOrId & kNameIsStringBit) != 0;
        std::wstring currentName;

        if (isNamed) {
            // NameOrId is an offset (relative to resource section base) to a
            // length-prefixed UTF-16LE string
            uint32_t nameOffset = 0;
            if (!AddU32(resourceBaseFileOffset, currentId, nameOffset) ||
                !IsWithinResourceBounds(data, nameOffset, sizeof(uint16_t),
                                        resourceBaseFileOffset, resourceEndFileOffset)) {
                continue;
            }
            currentName = ReadResourceName(data, nameOffset);
            // Use a synthetic ID of 0 for named resources
            currentId = 0;
        }

        // Propagate IDs through the tree levels
        uint32_t curType = typeId;
        uint32_t curName = nameId;
        bool     entryHasName = false;
        std::wstring entryName;

        switch (depth) {
        case 0:
            curType = currentId;
            if (isNamed) {
                entryHasName = true;
                entryName = std::move(currentName);
            }
            break;
        case 1:
            curName = currentId;
            if (isNamed) {
                entryHasName = true;
                entryName = std::move(currentName);
            }
            break;
        default:
            break;
        }

        // ---------------------------------------------------------------------
        // Navigate: subdirectory or leaf data entry
        // ---------------------------------------------------------------------
        const bool isSubdir = (entry.OffsetToDataOrSubdir & kOffsetIsSubdirBit) != 0;
        const uint32_t targetOffset = entry.OffsetToDataOrSubdir & kOffsetMask;

        if (isSubdir) {
            // Recurse into subdirectory
            uint32_t subdirFileOffset = 0;
            if (!AddU32(resourceBaseFileOffset, targetOffset, subdirFileOffset)) {
                continue;
            }

            // Validate before recursing
            if (!IsWithinResourceBounds(data, subdirFileOffset,
                                        static_cast<uint32_t>(sizeof(PE::ResourceDirectory)),
                                        resourceBaseFileOffset, resourceEndFileOffset))
            {
                continue;
            }

            // Avoid infinite loops: subdirectory must not point back to current
            if (subdirFileOffset == dirFileOffset) {
                continue;
            }

            ParseDirectory(
                data,
                subdirFileOffset,
                resourceBaseFileOffset,
                resourceEndFileOffset,
                resourceBaseRVA,
                depth + 1,
                curType,
                curName,
                out,
                entryCount);

        } else {
            // Leaf node: read ResourceDataEntry
            uint32_t dataEntryFileOffset = 0;
            if (!AddU32(resourceBaseFileOffset, targetOffset, dataEntryFileOffset) ||
                !IsWithinResourceBounds(data, dataEntryFileOffset, sizeof(PE::ResourceDataEntry),
                                        resourceBaseFileOffset, resourceEndFileOffset)) {
                continue;
            }

            PE::ResourceDataEntry dataEntry{};
            if (!SafeRead(data, dataEntryFileOffset, dataEntry)) {
                continue;
            }

            // Validate data bounds:
            // dataEntry.OffsetToData is an RVA — we need to check it relative
            // to the resource section RVA to compute the file offset
            if (dataEntry.Size == 0) {
                continue;
            }

            // Build the resource entry
            ResourceEntry resEntry;
            resEntry.type       = curType;
            resEntry.nameOrId   = curName;
            resEntry.languageId = currentId; // At depth 2, currentId is the language
            resEntry.dataRVA    = dataEntry.OffsetToData;
            resEntry.dataSize   = dataEntry.Size;
            resEntry.codePage   = dataEntry.CodePage;

            if (depth == 1 && entryHasName) {
                resEntry.hasName = true;
                resEntry.name    = std::move(entryName);
            } else if (depth == 0 && entryHasName) {
                // Named type — unusual but possible
                resEntry.hasName = true;
                resEntry.name    = std::move(entryName);
            }

            try {
                out.push_back(std::move(resEntry));
            } catch (const std::bad_alloc&) {
                return;
            }
            ++entryCount;
        }
    }
}

// ============================================================================
// ReadResourceName — Length-prefixed UTF-16LE string
// ============================================================================
// PE resource names are stored as: uint16_t length (in characters), followed
// by that many uint16_t code units (NOT null-terminated).

std::wstring ResourceParser::ReadResourceName(
    ByteSpan data,
    uint32_t nameFileOffset) noexcept
{
    try {
        // Read the 16-bit character count
        uint16_t charCount = 0;
        if (!SafeRead(data, nameFileOffset, charCount)) {
            return {};
        }

    if (charCount == 0) {
        return {};
    }

    // Cap to prevent absurd allocations
    if (charCount > kMaxResourceNameChars) {
        charCount = static_cast<uint16_t>(kMaxResourceNameChars);
    }

    const uint32_t stringOffset = nameFileOffset + sizeof(uint16_t);
    const uint32_t stringBytes  = static_cast<uint32_t>(charCount) * sizeof(uint16_t);

    if (!IsOffsetValid(data, stringOffset, stringBytes)) {
        return {};
    }

    // Build wstring from UTF-16LE code units
    std::wstring result;
    result.reserve(charCount);

    const uint8_t* ptr = data.data() + stringOffset;
    for (uint16_t i = 0; i < charCount; ++i) {
        uint16_t ch = 0;
        std::memcpy(&ch, ptr + i * sizeof(uint16_t), sizeof(uint16_t));
        result.push_back(static_cast<wchar_t>(ch));
    }

        return result;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

// ============================================================================
// FindByType — Filter resources by type ID
// ============================================================================

std::vector<ResourceEntry> ResourceParser::FindByType(
    const std::vector<ResourceEntry>& resources,
    uint32_t type) noexcept
{
    std::vector<ResourceEntry> result;
    try {
        result.reserve(16);

        for (const auto& entry : resources) {
            if (entry.type == type) {
                result.push_back(entry);
            }
        }
    } catch (const std::bad_alloc&) {
        result.clear();
    }

    return result;
}

// ============================================================================
// ExtractData — Get raw bytes of a resource from the file buffer
// ============================================================================

std::optional<ByteSpan> ResourceParser::ExtractData(
    ByteSpan data,
    const ResourceEntry& entry,
    [[maybe_unused]] uint32_t resourceDirFileOffset) noexcept
{
    if (entry.dataSize == 0 || entry.dataRVA == 0) {
        return std::nullopt;
    }

    if (data.empty() || data.size() > (std::numeric_limits<uint32_t>::max)()) {
        return std::nullopt;
    }

    // The resource data RVA needs to be converted to a file offset.
    // We need to find which section contains this RVA. For simplicity,
    // we compute the file offset as:
    //   fileOffset = resourceDirFileOffset + (dataRVA - resourceSectionRVA)
    // But we don't have resourceSectionRVA directly. The caller must pass
    // the correct resourceDirFileOffset.
    //
    // However, OffsetToData in ResourceDataEntry is already an RVA — it may
    // point anywhere in the PE's virtual address space. A common simplification
    // that works for well-formed PEs is to assume the resource data lives in
    // the same section as the resource directory.
    //
    // We compute: dataFileOffset from the PE file buffer.
    //
    // A robust approach: scan section headers to convert RVA→file offset.
    // Since we only have the flat buffer and the resource directory offset,
    // we scan backwards from the resource dir to find the DOS header and
    // section table. This is complex and error-prone, so instead we use
    // a heuristic that works for >99% of legitimate and malicious PEs:
    //
    // Many callers provide resourceDirFileOffset AND resourceDirRVA. The
    // difference gives us the section's file-to-RVA delta. But our API only
    // receives the file offset. We can infer the RVA from the resource data
    // entries themselves since they contain RVAs.
    //
    // For maximum robustness, attempt to locate the PE section table:

    // Step 1: Find the DOS header
    if (data.size() < sizeof(PE::DOSHeader)) {
        return std::nullopt;
    }

    PE::DOSHeader dos{};
    std::memcpy(&dos, data.data(), sizeof(dos));
    if (dos.e_magic != PE::kDOSMagic) {
        return std::nullopt;
    }

    const auto peOffset = static_cast<uint32_t>(dos.e_lfanew);
    if (peOffset == 0 || !IsOffsetValid(data, peOffset, 4 + sizeof(PE::FileHeader))) {
        return std::nullopt;
    }

    // Step 2: Read the file header to get section count
    uint32_t sig = 0;
    std::memcpy(&sig, data.data() + peOffset, sizeof(sig));
    if (sig != PE::kNTSignature) {
        return std::nullopt;
    }

    PE::FileHeader fileHdr{};
    std::memcpy(&fileHdr, data.data() + peOffset + 4, sizeof(fileHdr));

    uint32_t optionalHdrOffset = 0;
    uint32_t sectionTableOffset = 0;
    if (!AddU32(peOffset, 4U + static_cast<uint32_t>(sizeof(PE::FileHeader)), optionalHdrOffset) ||
        !AddU32(optionalHdrOffset, fileHdr.SizeOfOptionalHeader, sectionTableOffset)) {
        return std::nullopt;
    }

    const uint32_t numSections = fileHdr.NumberOfSections;
    if (numSections > PE::kMaxSections) {
        return std::nullopt;
    }

    // Step 3: Walk sections to convert dataRVA → file offset
    const auto dataRVA = static_cast<uint32_t>(entry.dataRVA);
    uint32_t dataFileOffset = 0;
    bool found = false;

    for (uint32_t s = 0; s < numSections; ++s) {
        uint32_t secOffset = 0;
        if (!AddU32(sectionTableOffset, s * static_cast<uint32_t>(sizeof(PE::SectionHeader)), secOffset)) {
            return std::nullopt;
        }

        PE::SectionHeader sec{};
        if (!SafeRead(data, secOffset, sec)) {
            break;
        }

        const uint32_t effectiveSize =
            ((sec.VirtualSize > sec.SizeOfRawData) ? sec.VirtualSize : sec.SizeOfRawData);
        uint32_t secEnd = 0;
        if (!AddU32(sec.VirtualAddress, effectiveSize, secEnd)) {
            continue;
        }

        if (dataRVA >= sec.VirtualAddress && dataRVA < secEnd) {
            const uint32_t delta = dataRVA - sec.VirtualAddress;
            // Ensure the data fits within the section's raw data
            if (delta < sec.SizeOfRawData &&
                (sec.SizeOfRawData - delta) >= entry.dataSize)
            {
                if (!AddU32(sec.PointerToRawData, delta, dataFileOffset)) {
                    return std::nullopt;
                }
                found = true;
            }
            break;
        }
    }

    if (!found) {
        return std::nullopt;
    }

    // Step 4: Validate final offset
    if (!IsOffsetValid(data, dataFileOffset, entry.dataSize)) {
        return std::nullopt;
    }

    return ByteSpan{ data.data() + dataFileOffset, entry.dataSize };
}

// ============================================================================
// CalculateEntropy — Shannon entropy (bits per byte)
// ============================================================================
// Output range: [0.0, 8.0]
//   0.0 = perfectly uniform single byte
//   ~7.0+ = encrypted, compressed, or random data
//
// This is a critical heuristic for malware analysis: legitimate resources
// (icons, manifests, dialogs) have entropy 3.0-5.5. Encrypted payloads
// hidden in resources will typically show entropy > 7.0.

double ResourceParser::CalculateEntropy(ByteSpan data) noexcept
{
    if (data.empty()) {
        return 0.0;
    }

    // Count byte frequencies
    uint32_t freq[256]{};
    for (const uint8_t byte : data) {
        ++freq[byte];
    }

    const auto totalBytes = static_cast<double>(data.size());
    double entropy = 0.0;

    for (uint32_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) {
            continue;
        }
        const double p = static_cast<double>(freq[i]) / totalBytes;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

} // namespace Phantom
