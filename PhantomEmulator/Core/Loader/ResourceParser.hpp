/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ResourceParser.hpp — PE resource directory tree parser
 *
 * Parses the three-level PE resource directory tree (Type → Name → Language)
 * into a flat list of ResourceEntry descriptors. Malware frequently hides
 * secondary payloads, encrypted configurations, shellcode, and additional
 * PE stages inside resources (especially RT_RCDATA, RT_BITMAP, RT_MANIFEST).
 *
 * Includes Shannon entropy calculation for detecting encrypted/packed
 * resource data — a strong indicator of embedded malware payloads.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "PEStructures.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// Resource Entry — Flattened leaf node from the resource tree
// ============================================================================

struct ResourceEntry {
    uint32_t     type       = 0;     // Resource type (RT_BITMAP=2, RT_RCDATA=10, etc.)
    uint32_t     nameOrId   = 0;     // Name ID or integer ID
    uint32_t     languageId = 0;     // Language ID (LCID)
    GuestAddress dataRVA    = 0;     // RVA of resource data
    uint32_t     dataSize   = 0;     // Size of resource data in bytes
    uint32_t     codePage   = 0;     // Code page for text resources
    bool         hasName    = false; // true if named resource (not integer ID)
    std::wstring name;               // UTF-16 name string (if hasName)
};

// ============================================================================
// Well-known resource type IDs
// ============================================================================

namespace ResourceType {
    static constexpr uint32_t Cursor       = 1;
    static constexpr uint32_t Bitmap       = 2;
    static constexpr uint32_t Icon         = 3;
    static constexpr uint32_t Menu         = 4;
    static constexpr uint32_t Dialog       = 5;
    static constexpr uint32_t String       = 6;
    static constexpr uint32_t FontDir      = 7;
    static constexpr uint32_t Font         = 8;
    static constexpr uint32_t Accelerator  = 9;
    static constexpr uint32_t RCData       = 10;
    static constexpr uint32_t MessageTable = 11;
    static constexpr uint32_t GroupCursor   = 12;
    static constexpr uint32_t GroupIcon     = 14;
    static constexpr uint32_t Version      = 16;
    static constexpr uint32_t Manifest     = 24;
} // namespace ResourceType

// ============================================================================
// ResourceParser — Recursive PE resource tree parser
// ============================================================================

class ResourceParser {
public:
    /// Parse all resources from a PE file's resource directory.
    /// @param data                  Raw PE file buffer (complete file).
    /// @param resourceDirRVA        RVA of the resource directory (data dir[2]).
    /// @param resourceDirSize       Size of the resource directory.
    /// @param resourceDirFileOffset File offset corresponding to resourceDirRVA.
    /// @return Flat vector of parsed resource entries.
    [[nodiscard]] static std::vector<ResourceEntry> Parse(
        ByteSpan data,
        uint32_t resourceDirRVA,
        uint32_t resourceDirSize,
        uint32_t resourceDirFileOffset) noexcept;

    /// Filter resources by type ID.
    [[nodiscard]] static std::vector<ResourceEntry> FindByType(
        const std::vector<ResourceEntry>& resources,
        uint32_t type) noexcept;

    /// Extract raw resource data bytes from the file buffer.
    /// @param data                  Raw PE file buffer.
    /// @param entry                 Resource entry to extract.
    /// @param resourceDirFileOffset File offset of the resource section base.
    /// @return Span into the file buffer, or nullopt on failure.
    [[nodiscard]] static std::optional<ByteSpan> ExtractData(
        ByteSpan data,
        const ResourceEntry& entry,
        uint32_t resourceDirFileOffset) noexcept;

    /// Calculate Shannon entropy of a data buffer.
    /// Values > 7.0 strongly suggest encryption or compression.
    [[nodiscard]] static double CalculateEntropy(ByteSpan data) noexcept;

private:
    /// Recursively parse a resource directory node.
    static void ParseDirectory(
        ByteSpan   data,
        uint32_t   dirFileOffset,         // File offset of this directory node
        uint32_t   resourceBaseFileOffset, // File offset of resource section start
        uint32_t   resourceEndFileOffset,  // Exclusive end of declared resource directory data
        uint32_t   resourceBaseRVA,        // RVA of resource section start
        uint32_t   depth,                  // Current recursion depth (0-indexed)
        uint32_t   typeId,                 // Type ID (set at depth 0)
        uint32_t   nameId,                 // Name/ID (set at depth 1)
        std::vector<ResourceEntry>& out,
        uint32_t&  entryCount) noexcept;

    /// Read a length-prefixed UTF-16LE resource name string.
    [[nodiscard]] static std::wstring ReadResourceName(
        ByteSpan data,
        uint32_t nameFileOffset) noexcept;
};

} // namespace Phantom
