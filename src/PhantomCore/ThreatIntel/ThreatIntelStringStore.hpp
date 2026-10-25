// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Persistent text of string-valued threat indicators
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file ThreatIntelStringStore.hpp
 * @brief The text behind every Domain, URL and Email indicator, interned and kept on disk.
 *
 * An IOCEntry holds a domain, URL or email as a reference (offset, length) into a string pool,
 * and the database never had one: nothing wrote the text anywhere, so every string indicator was
 * stored with offset 0 and only its length. Lookups then compared (offset, length), so a looked-up
 * domain matched any stored domain of the same length (task 345).
 *
 * This store gives those references something to point at. It is a sidecar file next to the
 * database (<database>.strings), append-only, loaded into memory at open. Every text is INTERNED:
 * one text has exactly one reference, so (offset, length) is an exact identity for the text and
 * comparing references compares texts. Offsets are file offsets of the text bytes and are never
 * below kFirstOffset, so a zero reference always means "no text".
 *
 * File layout:  "SSTISTR1" (8 bytes) | uint32 version | uint32 reserved | records...
 *               record = uint32 length (little endian) | length bytes of text
 * A record cut short by a crash is dropped at the next open and the file truncated to the last
 * complete record. Text stays where it was written for the life of the open store, so a returned
 * std::string_view is valid until Close().
 */

#pragma once

#include <Windows.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
namespace ThreatIntel {

/// A reference to one interned text: where its bytes start in the store, and how many there are.
struct InternedString {
    uint64_t offset = 0;
    uint32_t length = 0;
};

class ThreatIntelStringStore {
public:
    static constexpr char     kMagic[8] = {'S', 'S', 'T', 'I', 'S', 'T', 'R', '1'};
    static constexpr uint32_t kVersion = 1;
    static constexpr uint64_t kHeaderSize = 16;
    /// The lowest offset any text can have: the first record's length prefix follows the header.
    static constexpr uint64_t kFirstOffset = kHeaderSize + sizeof(uint32_t);
    /// Longer than any URL the IOC parser accepts, so a valid indicator always fits.
    static constexpr uint32_t kMaxStringLength = 64 * 1024;
    /// Bounds the memory the store may hold; interning beyond it fails instead of growing.
    static constexpr uint64_t kMaxTotalBytes = 512ULL * 1024 * 1024;

    ThreatIntelStringStore() = default;
    ~ThreatIntelStringStore();

    ThreatIntelStringStore(const ThreatIntelStringStore&) = delete;
    ThreatIntelStringStore& operator=(const ThreatIntelStringStore&) = delete;

    /// Opens or creates the file at path. A read-only store never writes, and refuses Intern.
    [[nodiscard]] bool Open(const std::wstring& path, bool readOnly) noexcept;
    void Close() noexcept;
    [[nodiscard]] bool IsOpen() const noexcept;

    /// The reference for text, writing it first if the store does not hold it yet. Fails for
    /// empty or oversized text, a read-only store, a full store or a failed write.
    [[nodiscard]] std::optional<InternedString> Intern(std::string_view text) noexcept;

    /// The reference for text if the store holds it. Never writes.
    [[nodiscard]] std::optional<InternedString> Find(std::string_view text) const noexcept;

    /// The text a reference names, or an empty view when the reference names no record.
    /// Valid until Close().
    [[nodiscard]] std::string_view Get(uint64_t offset, uint32_t length) const noexcept;

    /// True when (offset, length) is exactly one record of this store.
    [[nodiscard]] bool IsValidRef(uint64_t offset, uint32_t length) const noexcept;

    [[nodiscard]] bool Flush() noexcept;

    [[nodiscard]] size_t StringCount() const noexcept;
    [[nodiscard]] uint64_t SizeBytes() const noexcept;
    /// Bytes dropped at open because the last record was incomplete.
    [[nodiscard]] uint64_t TruncatedTailBytes() const noexcept;
    /// True when the file at open was unreadable and was moved aside for a fresh one.
    [[nodiscard]] bool ReplacedUnreadableFile() const noexcept;

private:
    struct Chunk {
        uint64_t fileStart = 0;   ///< File offset of the chunk's first byte
        size_t   capacity = 0;
        size_t   used = 0;
        std::unique_ptr<char[]> data;
    };

    [[nodiscard]] static uint64_t Hash(std::string_view text) noexcept;
    [[nodiscard]] std::optional<InternedString> FindLocked(std::string_view text, uint64_t hash) const noexcept;
    [[nodiscard]] std::string_view GetLocked(uint64_t offset, uint32_t length) const noexcept;
    [[nodiscard]] bool IsValidRefLocked(uint64_t offset, uint32_t length) const noexcept;
    /// Places a complete record (length prefix and text) in memory at file offset recordStart.
    [[nodiscard]] bool PlaceRecord(uint64_t recordStart, std::string_view text);
    [[nodiscard]] bool LoadExisting(HANDLE file, uint64_t fileSize);
    [[nodiscard]] bool WriteHeader(HANDLE file) noexcept;
    void ResetLocked() noexcept;

    mutable std::shared_mutex m_mutex;
    HANDLE   m_file = INVALID_HANDLE_VALUE;
    bool     m_open = false;
    bool     m_readOnly = true;
    uint64_t m_fileEnd = 0;          ///< File offset one past the last complete record
    uint64_t m_truncatedTail = 0;
    bool     m_replacedUnreadable = false;

    std::vector<Chunk> m_chunks;                                          ///< Ordered by fileStart
    std::vector<InternedString> m_records;                               ///< Ordered by offset
    std::unordered_map<uint64_t, std::vector<InternedString>> m_byHash;  ///< Interning index
};

}  // namespace ThreatIntel
}  // namespace ShadowStrike
