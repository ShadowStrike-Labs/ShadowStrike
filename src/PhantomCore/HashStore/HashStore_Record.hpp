/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once

// ============================================================================
// HashStore — On-disk hash signature record layout (internal header)
// ============================================================================
//
// This header is INTERNAL to the HashStore module. It defines the binary
// layout of a single hash signature entry as written by AddHash/AddHashBatch
// and consumed by Rebuild / Verify / Export* / FuzzyMatch / BuildDetectionResult.
//
// ------------------------------- LAYOUT V2 ----------------------------------
//
//   offset          size            field
//   -----------     ----            -----
//   +0              72              HashValue            (zero-copy, 8-byte aligned)
//   +72             28              HashSignatureRecord  (packed metadata header)
//   +100            nameLength      signatureName        (utf-8, not null-terminated)
//   +100 + nL       descLength      description          (utf-8, not null-terminated)
//   +100 + nL + dL  tagsJsonLength  tagsJson             (compact JSON array)
//
// Rationale for prepending the HashValue:
//   Multiple readers across the codebase (Rebuild, Export*, FuzzyMatch, etc.)
//   take signatureOffset out of the B+Tree and reinterpret_cast the byte at
//   that offset as a HashValue for zero-copy comparison and re-enumeration.
//   Placing HashValue at offset 0 of the record:
//     (1) preserves the existing zero-copy reader contract,
//     (2) keeps the HashValue's required 8-byte alignment intact (every
//         record is allocated at a page-aligned boundary by AllocateSignatureEntry),
//     (3) co-locates the hash bytes with their metadata for cache friendliness.
//
// Format versioning:
//   The 32-bit `magic` and `version` fields inside HashSignatureRecord allow
//   forward-compatible evolution. v1 was a metadata-only header (no inline
//   HashValue) and is no longer supported — readers reject records whose
//   magic byte sequence does not match HASH_RECORD_MAGIC.
//
// Security:
//   - All length fields are bounded (see MAX_RECORD_* constants below).
//   - Readers MUST validate the record magic before trusting any other
//     field, and MUST perform two-step bounds checks via the helpers in
//     this header (which use MemoryMappedView::GetAt internally).
//   - Writers MUST stay within the allocation returned by
//     AllocateSignatureEntry; the helper Layout::TotalRecordSize computes
//     the exact required size given the variable-length payload.
//
// ============================================================================

#include "../SignatureStore/SignatureFormat.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>

namespace ShadowStrike {
namespace HashStore {
namespace Record {

using ::ShadowStrike::SignatureStore::HashType;
using ::ShadowStrike::SignatureStore::HashValue;
using ::ShadowStrike::SignatureStore::ThreatLevel;
using ::ShadowStrike::SignatureStore::MemoryMappedView;

// ---------------------------------------------------------------------------
// Magic / version
// ---------------------------------------------------------------------------

inline constexpr uint32_t MAGIC   = 0x52535348u;  // 'HSSR' (little-endian)
inline constexpr uint32_t VERSION = 2u;           // V2: HashValue prefixed

// ---------------------------------------------------------------------------
// Bounded sizes — every length field in the on-disk header must be clamped
// to these maxima before being written, and validated against them on read.
// ---------------------------------------------------------------------------

inline constexpr size_t MAX_NAME_LEN     = 256;    // bytes
inline constexpr size_t MAX_DESC_LEN     = 4096;   // bytes
inline constexpr size_t MAX_TAGS_JSON_LEN = 8192;  // bytes (compact JSON)

// ---------------------------------------------------------------------------
// Packed on-disk metadata header (immediately follows the HashValue prefix).
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
struct Header {
    uint32_t magic;            // == MAGIC
    uint32_t version;          // == VERSION
    uint8_t  hashType;         // duplicates HashValue.type for cross-check
    uint8_t  threatLevel;      // ThreatLevel enumeration
    uint16_t nameLength;       // bytes, <= MAX_NAME_LEN
    uint32_t descLength;       // bytes, <= MAX_DESC_LEN
    uint32_t tagsJsonLength;   // bytes, <= MAX_TAGS_JSON_LEN
    uint64_t creationTime;     // seconds since POSIX epoch (std::time_t)
};
#pragma pack(pop)

static_assert(sizeof(Header) == 28,
    "HashStore::Record::Header must be exactly 28 bytes for on-disk stability");

// ---------------------------------------------------------------------------
// Layout offsets (computed once at compile time)
// ---------------------------------------------------------------------------

inline constexpr uint64_t HASH_OFFSET    = 0;
inline constexpr uint64_t HEADER_OFFSET  = sizeof(HashValue);                  // 72
inline constexpr uint64_t PAYLOAD_OFFSET = HEADER_OFFSET + sizeof(Header);     // 100

static_assert(HEADER_OFFSET % alignof(HashValue) == 0,
    "Record metadata must start at a HashValue-aligned offset");

// Total record byte count for a given variable-length payload.
[[nodiscard]] inline constexpr size_t TotalRecordSize(
    size_t nameLen, size_t descLen, size_t tagsJsonLen) noexcept
{
    return static_cast<size_t>(PAYLOAD_OFFSET) + nameLen + descLen + tagsJsonLen;
}

// ---------------------------------------------------------------------------
// Validity helpers
// ---------------------------------------------------------------------------

[[nodiscard]] inline bool IsValidThreatLevel(uint8_t raw) noexcept {
    switch (static_cast<ThreatLevel>(raw)) {
        case ThreatLevel::Info:
        case ThreatLevel::Low:
        case ThreatLevel::Medium:
        case ThreatLevel::High:
        case ThreatLevel::Critical:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline ThreatLevel ClampThreatLevel(uint8_t raw) noexcept {
    return IsValidThreatLevel(raw)
        ? static_cast<ThreatLevel>(raw)
        : ThreatLevel::Medium;
}

// ---------------------------------------------------------------------------
// Zero-copy accessors
// ---------------------------------------------------------------------------

// Returns a pointer to the inline HashValue at signatureOffset, or nullptr if
// the offset is out of bounds. Performs an overflow-safe range check.
[[nodiscard]] inline const HashValue* GetHash(
    const MemoryMappedView& view, uint64_t signatureOffset) noexcept
{
    return view.GetAt<HashValue>(signatureOffset);
}

// Returns a pointer to the on-disk Header that follows the HashValue prefix,
// or nullptr if the offset/magic is invalid.
[[nodiscard]] inline const Header* GetHeader(
    const MemoryMappedView& view, uint64_t signatureOffset) noexcept
{
    // Two-step bounds check: signatureOffset itself must allow at least
    // HEADER_OFFSET + sizeof(Header) bytes inside the mapping.
    if (signatureOffset > view.fileSize) return nullptr;
    if (PAYLOAD_OFFSET > view.fileSize - signatureOffset) return nullptr;

    const Header* rec = view.GetAt<Header>(signatureOffset + HEADER_OFFSET);
    if (!rec) return nullptr;
    if (rec->magic != MAGIC) return nullptr;
    return rec;
}

// Reads the signature name from the record's payload. Returns an empty
// string for malformed / out-of-bounds / oversize records.
[[nodiscard]] inline std::string ReadName(
    const MemoryMappedView& view, uint64_t signatureOffset) noexcept
{
    const Header* rec = GetHeader(view, signatureOffset);
    if (!rec) return {};
    if (rec->nameLength == 0 || rec->nameLength > MAX_NAME_LEN) return {};

    const uint64_t nameStart = signatureOffset + PAYLOAD_OFFSET;
    if (nameStart > view.fileSize) return {};
    if (rec->nameLength > view.fileSize - nameStart) return {};

    const auto* base = static_cast<const uint8_t*>(view.baseAddress);
    if (!base) return {};

    try {
        return std::string(
            reinterpret_cast<const char*>(base + nameStart),
            rec->nameLength);
    } catch (...) {
        return {};
    }
}

// Reads the description from the record's payload (empty on any failure).
[[nodiscard]] inline std::string ReadDescription(
    const MemoryMappedView& view, uint64_t signatureOffset) noexcept
{
    const Header* rec = GetHeader(view, signatureOffset);
    if (!rec) return {};
    if (rec->descLength == 0 || rec->descLength > MAX_DESC_LEN) return {};

    const uint64_t descStart = signatureOffset + PAYLOAD_OFFSET + rec->nameLength;
    if (descStart > view.fileSize) return {};
    if (rec->descLength > view.fileSize - descStart) return {};

    const auto* base = static_cast<const uint8_t*>(view.baseAddress);
    if (!base) return {};

    try {
        return std::string(
            reinterpret_cast<const char*>(base + descStart),
            rec->descLength);
    } catch (...) {
        return {};
    }
}

// Reads the tags-JSON blob from the record's payload (empty on any failure).
[[nodiscard]] inline std::string ReadTagsJson(
    const MemoryMappedView& view, uint64_t signatureOffset) noexcept
{
    const Header* rec = GetHeader(view, signatureOffset);
    if (!rec) return {};
    if (rec->tagsJsonLength == 0 || rec->tagsJsonLength > MAX_TAGS_JSON_LEN) return {};

    const uint64_t tagsStart = signatureOffset + PAYLOAD_OFFSET +
                                rec->nameLength + rec->descLength;
    if (tagsStart > view.fileSize) return {};
    if (rec->tagsJsonLength > view.fileSize - tagsStart) return {};

    const auto* base = static_cast<const uint8_t*>(view.baseAddress);
    if (!base) return {};

    try {
        return std::string(
            reinterpret_cast<const char*>(base + tagsStart),
            rec->tagsJsonLength);
    } catch (...) {
        return {};
    }
}

[[nodiscard]] inline ThreatLevel ReadThreatLevel(
    const MemoryMappedView& view, uint64_t signatureOffset) noexcept
{
    const Header* rec = GetHeader(view, signatureOffset);
    if (!rec) return ThreatLevel::Medium;
    return ClampThreatLevel(rec->threatLevel);
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------
//
// Writes a complete V2 record (HashValue + Header + payload) into the
// memory-mapped view at the given offset. All sub-lengths are clamped to
// the documented maxima; the caller MUST have reserved at least
// TotalRecordSize(clamped sizes) bytes via AllocateSignatureEntry before
// invoking this helper.
//
// Returns false if:
//   - the view is null / read-only,
//   - the offset is out of bounds,
//   - the computed record extent overflows uint64_t or exceeds the file size.
//
[[nodiscard]] inline bool Write(
    MemoryMappedView& view,
    uint64_t signatureOffset,
    const HashValue& hash,
    ThreatLevel threatLevel,
    const std::string& name,
    const std::string& description,
    const std::string& tagsJson) noexcept
{
    if (!view.IsValid() || view.readOnly) return false;

    const size_t nameLen     = std::min(name.size(),        MAX_NAME_LEN);
    const size_t descLen     = std::min(description.size(), MAX_DESC_LEN);
    const size_t tagsJsonLen = std::min(tagsJson.size(),    MAX_TAGS_JSON_LEN);

    const size_t totalSize = TotalRecordSize(nameLen, descLen, tagsJsonLen);

    if (signatureOffset > view.fileSize) return false;
    if (totalSize > view.fileSize - signatureOffset) return false;

    auto* base = static_cast<uint8_t*>(view.baseAddress);
    if (!base) return false;

    // 1. Inline HashValue (binary copy preserves alignment and type/length).
    auto* hashDst = view.GetAtMutable<HashValue>(signatureOffset);
    if (!hashDst) return false;
    std::memcpy(hashDst, &hash, sizeof(HashValue));

    // 2. Metadata header.
    auto* rec = view.GetAtMutable<Header>(signatureOffset + HEADER_OFFSET);
    if (!rec) return false;

    rec->magic          = MAGIC;
    rec->version        = VERSION;
    rec->hashType       = static_cast<uint8_t>(hash.type);
    rec->threatLevel    = static_cast<uint8_t>(
        IsValidThreatLevel(static_cast<uint8_t>(threatLevel))
            ? threatLevel
            : ThreatLevel::Medium);
    rec->nameLength     = static_cast<uint16_t>(nameLen);
    rec->descLength     = static_cast<uint32_t>(descLen);
    rec->tagsJsonLength = static_cast<uint32_t>(tagsJsonLen);
    rec->creationTime   = static_cast<uint64_t>(std::time(nullptr));

    // 3. Variable-length payload (name | description | tagsJson).
    uint8_t* dst = base + signatureOffset + PAYLOAD_OFFSET;
    if (nameLen)     { std::memcpy(dst, name.data(),        nameLen);     dst += nameLen; }
    if (descLen)     { std::memcpy(dst, description.data(), descLen);     dst += descLen; }
    if (tagsJsonLen) { std::memcpy(dst, tagsJson.data(),    tagsJsonLen); }

    return true;
}

} // namespace Record
} // namespace HashStore
} // namespace ShadowStrike
