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

#include "pch.h"
#include "ThreatIntelStringStore.hpp"

#include <algorithm>
#include <cstring>
#include <new>

namespace ShadowStrike {
namespace ThreatIntel {

namespace {

constexpr size_t kChunkSize = 1024 * 1024;

[[nodiscard]] bool WriteAll(HANDLE file, const void* data, size_t size) noexcept {
    const auto* bytes = static_cast<const uint8_t*>(data);
    while (size > 0) {
        const DWORD part = static_cast<DWORD>(std::min<size_t>(size, 1u << 30));
        DWORD written = 0;
        if (!::WriteFile(file, bytes, part, &written, nullptr) || written != part) {
            return false;
        }
        bytes += part;
        size -= part;
    }
    return true;
}

[[nodiscard]] bool SeekTo(HANDLE file, uint64_t offset) noexcept {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    return ::SetFilePointerEx(file, position, nullptr, FILE_BEGIN) != FALSE;
}

// Sequential reads through a fixed buffer: one ReadFile per megabyte, not per record.
class BufferedReader {
public:
    explicit BufferedReader(HANDLE file) : m_file(file), m_buffer(kChunkSize) {}

    // Reads exactly size bytes; false at end of file or on a read error.
    [[nodiscard]] bool Read(void* out, size_t size) {
        auto* dst = static_cast<uint8_t*>(out);
        while (size > 0) {
            if (m_pos == m_len) {
                DWORD got = 0;
                if (!::ReadFile(m_file, m_buffer.data(), static_cast<DWORD>(m_buffer.size()), &got, nullptr) ||
                    got == 0) {
                    return false;
                }
                m_pos = 0;
                m_len = got;
            }
            const size_t take = std::min(size, m_len - m_pos);
            std::memcpy(dst, m_buffer.data() + m_pos, take);
            m_pos += take;
            dst += take;
            size -= take;
        }
        return true;
    }

private:
    HANDLE m_file;
    std::vector<uint8_t> m_buffer;
    size_t m_pos = 0;
    size_t m_len = 0;
};

}  // namespace

ThreatIntelStringStore::~ThreatIntelStringStore() {
    Close();
}

uint64_t ThreatIntelStringStore::Hash(std::string_view text) noexcept {
    uint64_t hash = 14695981039346656037ULL;  // FNV-1a
    for (const char c : text) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool ThreatIntelStringStore::WriteHeader(HANDLE file) noexcept {
    uint8_t header[kHeaderSize]{};
    std::memcpy(header, kMagic, sizeof(kMagic));
    std::memcpy(header + 8, &kVersion, sizeof(kVersion));
    return SeekTo(file, 0) && WriteAll(file, header, sizeof(header)) && ::SetEndOfFile(file) != FALSE;
}

void ThreatIntelStringStore::ResetLocked() noexcept {
    m_chunks.clear();
    m_records.clear();
    m_byHash.clear();
    m_fileEnd = kHeaderSize;
}

bool ThreatIntelStringStore::Open(const std::wstring& path, bool readOnly) noexcept {
    std::unique_lock lock(m_mutex);
    if (m_open || path.empty()) {
        return false;
    }
    ResetLocked();
    m_truncatedTail = 0;
    m_replacedUnreadable = false;
    m_readOnly = readOnly;

    try {
        HANDLE file = ::CreateFileW(path.c_str(), readOnly ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE),
                                    FILE_SHARE_READ, nullptr, readOnly ? OPEN_EXISTING : OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            const DWORD error = ::GetLastError();
            if (readOnly && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) {
                m_open = true;  // A read-only database without text holds no string indicators.
                return true;
            }
            return false;
        }

        LARGE_INTEGER size{};
        if (!::GetFileSizeEx(file, &size)) {
            ::CloseHandle(file);
            return false;
        }

        bool usable = size.QuadPart == 0 || LoadExisting(file, static_cast<uint64_t>(size.QuadPart));
        if (!usable && !readOnly) {
            // Unreadable (wrong magic, version or a header cut short). Keep the bytes for
            // diagnosis and start empty; entries that pointed into it are revoked by the
            // database at open because their references no longer validate.
            ::CloseHandle(file);
            const std::wstring aside = path + L".unreadable-" + std::to_wstring(::GetTickCount64());
            if (!::MoveFileExW(path.c_str(), aside.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                return false;
            }
            file = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                 CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                return false;
            }
            ResetLocked();
            m_replacedUnreadable = true;
            size.QuadPart = 0;
        } else if (!usable) {
            ResetLocked();  // Read-only: treat as empty, never modify.
        }

        if (!readOnly) {
            if (size.QuadPart == 0) {
                if (!WriteHeader(file)) {
                    ::CloseHandle(file);
                    return false;
                }
                m_fileEnd = kHeaderSize;
            } else if (m_truncatedTail > 0) {
                // Drop the incomplete last record so the next append starts on a boundary.
                if (!SeekTo(file, m_fileEnd) || !::SetEndOfFile(file)) {
                    ::CloseHandle(file);
                    ResetLocked();
                    return false;
                }
            }
            m_file = file;
        } else {
            ::CloseHandle(file);
        }
        m_open = true;
        return true;
    } catch (...) {
        ResetLocked();
        return false;
    }
}

bool ThreatIntelStringStore::LoadExisting(HANDLE file, uint64_t fileSize) {
    if (fileSize < kHeaderSize || fileSize > kMaxTotalBytes || !SeekTo(file, 0)) {
        return false;
    }
    BufferedReader reader(file);
    uint8_t header[kHeaderSize]{};
    if (!reader.Read(header, sizeof(header)) || std::memcmp(header, kMagic, sizeof(kMagic)) != 0) {
        return false;
    }
    uint32_t version = 0;
    std::memcpy(&version, header + 8, sizeof(version));
    if (version != kVersion) {
        return false;
    }

    uint64_t position = kHeaderSize;
    std::string text;
    while (position < fileSize) {
        uint32_t length = 0;
        if (fileSize - position < sizeof(length) || !reader.Read(&length, sizeof(length))) {
            break;
        }
        if (length == 0 || length > kMaxStringLength || fileSize - position - sizeof(length) < length) {
            break;
        }
        text.resize(length);
        if (!reader.Read(text.data(), length)) {
            break;
        }
        if (!PlaceRecord(position, text)) {
            return false;
        }
        position += sizeof(length) + length;
    }
    m_fileEnd = position;
    m_truncatedTail = fileSize - position;
    return true;
}

bool ThreatIntelStringStore::PlaceRecord(uint64_t recordStart, std::string_view text) {
    const auto length = static_cast<uint32_t>(text.size());
    const size_t recordSize = sizeof(length) + text.size();
    if (m_chunks.empty() || m_chunks.back().capacity - m_chunks.back().used < recordSize ||
        m_chunks.back().fileStart + m_chunks.back().used != recordStart) {
        Chunk chunk;
        chunk.fileStart = recordStart;
        chunk.capacity = std::max(kChunkSize, recordSize);
        chunk.data = std::make_unique<char[]>(chunk.capacity);
        m_chunks.push_back(std::move(chunk));
    }
    Chunk& chunk = m_chunks.back();
    std::memcpy(chunk.data.get() + chunk.used, &length, sizeof(length));
    std::memcpy(chunk.data.get() + chunk.used + sizeof(length), text.data(), text.size());
    chunk.used += recordSize;

    const InternedString ref{recordStart + sizeof(length), length};
    m_records.push_back(ref);
    const uint64_t hash = Hash(text);
    if (!FindLocked(text, hash)) {
        m_byHash[hash].push_back(ref);
    }
    return true;
}

void ThreatIntelStringStore::Close() noexcept {
    std::unique_lock lock(m_mutex);
    if (m_file != INVALID_HANDLE_VALUE) {
        ::FlushFileBuffers(m_file);
        ::CloseHandle(m_file);
        m_file = INVALID_HANDLE_VALUE;
    }
    ResetLocked();
    m_open = false;
}

bool ThreatIntelStringStore::IsOpen() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_open;
}

std::string_view ThreatIntelStringStore::GetLocked(uint64_t offset, uint32_t length) const noexcept {
    if (offset < kFirstOffset || length == 0 || m_chunks.empty()) {
        return {};
    }
    const uint64_t recordStart = offset - sizeof(uint32_t);
    auto it = std::upper_bound(m_chunks.begin(), m_chunks.end(), recordStart,
                               [](uint64_t value, const Chunk& chunk) { return value < chunk.fileStart; });
    if (it == m_chunks.begin()) {
        return {};
    }
    const Chunk& chunk = *(it - 1);
    const uint64_t inChunk = recordStart - chunk.fileStart;
    if (inChunk + sizeof(uint32_t) + length > chunk.used) {
        return {};
    }
    return std::string_view(chunk.data.get() + inChunk + sizeof(uint32_t), length);
}

std::optional<InternedString> ThreatIntelStringStore::FindLocked(std::string_view text, uint64_t hash) const noexcept {
    const auto bucket = m_byHash.find(hash);
    if (bucket == m_byHash.end()) {
        return std::nullopt;
    }
    for (const auto& ref : bucket->second) {
        if (ref.length == text.size() && GetLocked(ref.offset, ref.length) == text) {
            return ref;
        }
    }
    return std::nullopt;
}

std::optional<InternedString> ThreatIntelStringStore::Intern(std::string_view text) noexcept {
    if (text.empty() || text.size() > kMaxStringLength) {
        return std::nullopt;
    }
    std::unique_lock lock(m_mutex);
    if (!m_open) {
        return std::nullopt;
    }
    const uint64_t hash = Hash(text);
    if (const auto existing = FindLocked(text, hash)) {
        return existing;
    }
    if (m_readOnly || m_file == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    const auto length = static_cast<uint32_t>(text.size());
    if (m_fileEnd + sizeof(length) + length > kMaxTotalBytes) {
        return std::nullopt;
    }

    const uint64_t recordStart = m_fileEnd;
    try {
        std::string record(sizeof(length) + text.size(), '\0');
        std::memcpy(record.data(), &length, sizeof(length));
        std::memcpy(record.data() + sizeof(length), text.data(), text.size());
        if (!SeekTo(m_file, recordStart) || !WriteAll(m_file, record.data(), record.size())) {
            (void)SeekTo(m_file, recordStart);
            (void)::SetEndOfFile(m_file);
            return std::nullopt;
        }
        if (!PlaceRecord(recordStart, text)) {
            (void)SeekTo(m_file, recordStart);
            (void)::SetEndOfFile(m_file);
            return std::nullopt;
        }
    } catch (...) {
        (void)SeekTo(m_file, recordStart);
        (void)::SetEndOfFile(m_file);
        return std::nullopt;
    }
    m_fileEnd = recordStart + sizeof(length) + length;
    return InternedString{recordStart + sizeof(length), length};
}

std::optional<InternedString> ThreatIntelStringStore::Find(std::string_view text) const noexcept {
    if (text.empty() || text.size() > kMaxStringLength) {
        return std::nullopt;
    }
    std::shared_lock lock(m_mutex);
    return FindLocked(text, Hash(text));
}

std::string_view ThreatIntelStringStore::Get(uint64_t offset, uint32_t length) const noexcept {
    std::shared_lock lock(m_mutex);
    return IsValidRefLocked(offset, length) ? GetLocked(offset, length) : std::string_view{};
}

bool ThreatIntelStringStore::IsValidRefLocked(uint64_t offset, uint32_t length) const noexcept {
    const auto it = std::lower_bound(m_records.begin(), m_records.end(), offset,
                                     [](const InternedString& ref, uint64_t value) { return ref.offset < value; });
    return it != m_records.end() && it->offset == offset && it->length == length;
}

bool ThreatIntelStringStore::IsValidRef(uint64_t offset, uint32_t length) const noexcept {
    std::shared_lock lock(m_mutex);
    return IsValidRefLocked(offset, length);
}

bool ThreatIntelStringStore::Flush() noexcept {
    std::shared_lock lock(m_mutex);
    return m_file == INVALID_HANDLE_VALUE || ::FlushFileBuffers(m_file) != FALSE;
}

size_t ThreatIntelStringStore::StringCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_records.size();
}

uint64_t ThreatIntelStringStore::SizeBytes() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_fileEnd;
}

uint64_t ThreatIntelStringStore::TruncatedTailBytes() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_truncatedTail;
}

bool ThreatIntelStringStore::ReplacedUnreadableFile() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_replacedUnreadable;
}

}  // namespace ThreatIntel
}  // namespace ShadowStrike
