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
#include "pch.h"
#include "Products/Community/PhantomEDR/LiveResponse/FileInspector.hpp"

#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/PE_sig_verf.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>

namespace ShadowStrike::Products::PhantomEDR::LiveResponse {

class FileInspectorImpl final {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
    std::vector<std::wstring> allowedRoots;
};

namespace {

using ShadowStrike::Utils::Logger;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace HashUtils = ShadowStrike::Utils::HashUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;
namespace PESignature = ShadowStrike::Utils::pe_sig_utils;

constexpr uint64_t kWindowsEpochOffset = 116444736000000000ULL;
constexpr uint32_t kMaxWalkResults = 50000;

[[nodiscard]] std::chrono::system_clock::time_point FileTimeToSystemTime(const FILETIME& fileTime) noexcept {
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;

    if (value.QuadPart <= kWindowsEpochOffset) {
        return {};
    }

    using HundredNanoseconds = std::chrono::duration<int64_t, std::ratio<1, 10000000>>;
    const auto unixTicks = static_cast<int64_t>(value.QuadPart - kWindowsEpochOffset);
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(HundredNanoseconds{ unixTicks }) };
}

[[nodiscard]] std::wstring LeafName(std::wstring_view path) {
    const size_t separator = path.find_last_of(L'\\');
    return separator == std::wstring_view::npos ? std::wstring(path) : std::wstring(path.substr(separator + 1));
}

[[nodiscard]] bool IsPortableExecutablePath(std::wstring_view path) {
    const std::wstring lower = StringUtils::ToLowerCopy(path);
    return lower.ends_with(L".exe")
        || lower.ends_with(L".dll")
        || lower.ends_with(L".sys")
        || lower.ends_with(L".ocx")
        || lower.ends_with(L".scr")
        || lower.ends_with(L".cpl");
}

[[nodiscard]] bool WildcardMatch(std::wstring_view value, std::wstring_view pattern) noexcept {
    size_t valueIndex = 0;
    size_t patternIndex = 0;
    size_t lastStar = std::wstring_view::npos;
    size_t backtrack = 0;

    while (valueIndex < value.size()) {
        if (patternIndex < pattern.size()
            && (std::towlower(pattern[patternIndex]) == std::towlower(value[valueIndex]) || pattern[patternIndex] == L'?')) {
            ++valueIndex;
            ++patternIndex;
            continue;
        }

        if (patternIndex < pattern.size() && pattern[patternIndex] == L'*') {
            lastStar = patternIndex++;
            backtrack = valueIndex;
            continue;
        }

        if (lastStar != std::wstring_view::npos) {
            patternIndex = lastStar + 1;
            valueIndex = ++backtrack;
            continue;
        }

        return false;
    }

    while (patternIndex < pattern.size() && pattern[patternIndex] == L'*') {
        ++patternIndex;
    }

    return patternIndex == pattern.size();
}

[[nodiscard]] FileEntry MakeFileEntry(const std::wstring& path, const FileUtils::FileStat& stat) {
    return FileEntry{
        .path = path,
        .name = LeafName(path),
        .isDirectory = stat.isDirectory,
        .size = stat.size,
        .createdAt = FileTimeToSystemTime(stat.creation),
        .modifiedAt = FileTimeToSystemTime(stat.lastWrite),
        .accessedAt = FileTimeToSystemTime(stat.lastAccess),
        .attributes = stat.attributes,
        .sha256 = {},
        .isSigned = false,
        .isHidden = stat.isHidden,
        .isSystem = stat.isSystem
    };
}

[[nodiscard]] std::string ComputeHashInternal(std::wstring_view path, const HashUtils::Algorithm algorithm) {
    std::vector<uint8_t> digest;
    HashUtils::Error error{};
    if (!HashUtils::ComputeFile(algorithm, path, digest, &error)) {
        return {};
    }
    return HashUtils::ToHexLower(digest);
}

[[nodiscard]] bool IsPathAllowed(const FileInspectorImpl& impl, std::wstring_view path) {
    if (impl.allowedRoots.empty()) {
        return false;
    }

    for (const auto& root : impl.allowedRoots) {
        FileUtils::Error error{};
        if (FileUtils::IsPathUnderRoot(path, root, true, &error)) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] std::optional<std::wstring> NormalizeAndValidatePath(const FileInspectorImpl& impl, std::wstring_view path) {
    FileUtils::Error error{};
    const std::wstring normalized = FileUtils::NormalizePath(path, true, &error);
    if (normalized.empty() || !IsPathAllowed(impl, normalized)) {
        return std::nullopt;
    }
    return normalized;
}

[[nodiscard]] bool PopulateSignatureInfo(std::wstring_view path, FileEntry& entry) {
    if (!IsPortableExecutablePath(path)) {
        return true;
    }

    PESignature::PEFileSignatureVerifier verifier;
    verifier.SetRevocationMode(PESignature::RevocationMode::OfflineAllowed);

    PESignature::SignatureInfo signatureInfo{};
    PESignature::Error error{};
    const bool verified = verifier.VerifyPESignature(path, signatureInfo, &error);
    entry.isSigned = signatureInfo.isSigned && signatureInfo.isVerified && signatureInfo.isChainTrusted && verified;
    return true;
}

[[nodiscard]] std::optional<FileEntry> InspectFileUnlocked(const FileInspectorImpl& impl, std::wstring_view path) {
    const auto normalizedPath = NormalizeAndValidatePath(impl, path);
    if (!normalizedPath.has_value()) {
        return std::nullopt;
    }

    FileUtils::FileStat stat{};
    FileUtils::Error error{};
    if (!FileUtils::Stat(*normalizedPath, stat, &error) || !stat.exists || stat.isDirectory) {
        return std::nullopt;
    }

    FileEntry entry = MakeFileEntry(*normalizedPath, stat);
    entry.sha256 = ComputeHashInternal(*normalizedPath, HashUtils::Algorithm::SHA256);
    (void)PopulateSignatureInfo(*normalizedPath, entry);

    std::vector<FileUtils::AlternateStreamInfo> streams;
    if (FileUtils::ListAlternateStreams(*normalizedPath, streams, &error) && !streams.empty()) {
        Logger::Warn("FileInspector: alternate data streams detected on {}", StringUtils::ToNarrow(*normalizedPath));
    }

    return entry;
}

} // namespace

FileInspector::FileInspector()
    : m_impl(std::make_unique<FileInspectorImpl>()) {
}

FileInspector::~FileInspector() = default;

FileInspector& FileInspector::Instance() {
    static FileInspector instance;
    return instance;
}

bool FileInspector::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("FileInspector: initialized");
    return true;
}

void FileInspector::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->allowedRoots.clear();
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("FileInspector: shutdown complete");
}

bool FileInspector::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

void FileInspector::SetAllowedRoots(const std::vector<std::wstring>& roots) {
    std::unique_lock lock(m_impl->mutex);

    std::vector<std::wstring> normalizedRoots;
    normalizedRoots.reserve(roots.size());
    for (const auto& root : roots) {
        FileUtils::Error error{};
        const std::wstring normalized = FileUtils::NormalizePath(root, true, &error);
        if (normalized.empty()) {
            Logger::Warn("FileInspector: skipped invalid allowed root");
            continue;
        }
        normalizedRoots.push_back(normalized);
    }

    std::ranges::sort(normalizedRoots);
    normalizedRoots.erase(std::unique(normalizedRoots.begin(), normalizedRoots.end()), normalizedRoots.end());
    m_impl->allowedRoots = std::move(normalizedRoots);
    Logger::Info("FileInspector: configured {} allowed roots", m_impl->allowedRoots.size());
}

std::vector<FileEntry> FileInspector::ListDirectory(
    std::wstring_view path,
    const bool recursive,
    const uint32_t maxDepth,
    const uint32_t maxResults) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("FileInspector: ListDirectory requested before initialization");
        return {};
    }

    const auto normalizedPath = NormalizeAndValidatePath(*m_impl, path);
    if (!normalizedPath.has_value()) {
        Logger::Warn("FileInspector: path validation failed for ListDirectory");
        return {};
    }

    const uint32_t effectiveMaxResults = std::min<uint32_t>(maxResults == 0 ? 1U : maxResults, kMaxWalkResults);
    FileUtils::WalkOptions options{};
    options.recursive = recursive;
    options.includeDirs = true;
    options.followReparsePoints = false;
    options.maxDepth = recursive ? std::min<size_t>(maxDepth, 16U) : 0U;

    std::vector<FileEntry> entries;
    entries.reserve(effectiveMaxResults);

    uint32_t seen = 0;
    FileUtils::Error error{};
    (void)FileUtils::WalkDirectory(*normalizedPath, options,
        [&](const std::wstring& fullPath, const WIN32_FIND_DATAW&) {
            if (seen >= effectiveMaxResults) {
                return false;
            }

            FileUtils::FileStat stat{};
            FileUtils::Error statError{};
            if (!FileUtils::Stat(fullPath, stat, &statError)) {
                return true;
            }

            entries.push_back(MakeFileEntry(fullPath, stat));
            ++seen;
            return true;
        }, &error);

    std::ranges::sort(entries, [](const auto& left, const auto& right) {
        return StringUtils::ToLowerCopy(left.path) < StringUtils::ToLowerCopy(right.path);
    });

    Logger::Debug("FileInspector: listed {} entries under {}", entries.size(), StringUtils::ToNarrow(*normalizedPath));
    return entries;
}

std::optional<FileEntry> FileInspector::InspectFile(std::wstring_view path) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("FileInspector: InspectFile requested before initialization");
        return std::nullopt;
    }

    const auto entry = InspectFileUnlocked(*m_impl, path);
    if (!entry.has_value()) {
        Logger::Warn("FileInspector: path validation failed for InspectFile");
        return std::nullopt;
    }
    return entry;
}

std::string FileInspector::ComputeHash(std::wstring_view path, const HashUtils::Algorithm alg) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("FileInspector: ComputeHash requested before initialization");
        return {};
    }

    const auto normalizedPath = NormalizeAndValidatePath(*m_impl, path);
    if (!normalizedPath.has_value()) {
        return {};
    }

    return ComputeHashInternal(*normalizedPath, alg);
}

std::vector<FileTimelineEntry> FileInspector::GetFileTimeline(
    std::wstring_view rootPath,
    const std::chrono::system_clock::time_point startTime,
    const std::chrono::system_clock::time_point endTime,
    const uint32_t maxResults) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire) || endTime < startTime) {
        return {};
    }

    const auto normalizedPath = NormalizeAndValidatePath(*m_impl, rootPath);
    if (!normalizedPath.has_value()) {
        return {};
    }

    const uint32_t effectiveMaxResults = std::min<uint32_t>(maxResults == 0 ? 1U : maxResults, kMaxWalkResults);
    FileUtils::WalkOptions options{};
    options.recursive = true;
    options.includeDirs = false;
    options.followReparsePoints = false;
    options.maxDepth = 8;

    std::vector<FileTimelineEntry> timeline;
    timeline.reserve(effectiveMaxResults);

    uint32_t scanned = 0;
    FileUtils::Error error{};
    (void)FileUtils::WalkDirectory(*normalizedPath, options,
        [&](const std::wstring& fullPath, const WIN32_FIND_DATAW&) {
            if (timeline.size() >= effectiveMaxResults || scanned >= kMaxWalkResults) {
                return false;
            }
            ++scanned;

            FileUtils::FileStat stat{};
            FileUtils::Error statError{};
            if (!FileUtils::Stat(fullPath, stat, &statError) || stat.isDirectory) {
                return true;
            }

            const auto created = FileTimeToSystemTime(stat.creation);
            const auto modified = FileTimeToSystemTime(stat.lastWrite);
            const auto accessed = FileTimeToSystemTime(stat.lastAccess);

            auto appendIfInRange = [&](const auto timestamp, const FileTimelineEntry::Action action, const char* details) {
                if (timestamp >= startTime && timestamp <= endTime && timeline.size() < effectiveMaxResults) {
                    timeline.push_back(FileTimelineEntry{
                        .path = fullPath,
                        .timestamp = timestamp,
                        .action = action,
                        .details = details
                    });
                }
            };

            appendIfInRange(created, FileTimelineEntry::Action::Created, "creation timestamp");
            appendIfInRange(modified, FileTimelineEntry::Action::Modified, "last write timestamp");
            appendIfInRange(accessed, FileTimelineEntry::Action::Accessed, "last access timestamp");
            return timeline.size() < effectiveMaxResults;
        }, &error);

    std::ranges::sort(timeline, [](const auto& left, const auto& right) {
        return left.timestamp < right.timestamp;
    });

    return timeline;
}

std::vector<FileEntry> FileInspector::FindByHash(
    std::wstring_view rootPath,
    std::string_view sha256Hash,
    const uint32_t maxResults) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire) || sha256Hash.empty()) {
        return {};
    }

    const auto normalizedPath = NormalizeAndValidatePath(*m_impl, rootPath);
    if (!normalizedPath.has_value()) {
        return {};
    }

    std::string normalizedHash(sha256Hash);
    std::ranges::transform(normalizedHash, normalizedHash.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    const uint32_t effectiveMaxResults = std::min<uint32_t>(maxResults == 0 ? 1U : maxResults, 100U);
    FileUtils::WalkOptions options{};
    options.recursive = true;
    options.includeDirs = false;
    options.followReparsePoints = false;
    options.maxDepth = 8;

    std::vector<FileEntry> matches;
    matches.reserve(effectiveMaxResults);

    uint32_t scanned = 0;
    FileUtils::Error error{};
    (void)FileUtils::WalkDirectory(*normalizedPath, options,
        [&](const std::wstring& fullPath, const WIN32_FIND_DATAW&) {
            if (matches.size() >= effectiveMaxResults || scanned >= kMaxWalkResults) {
                return false;
            }
            ++scanned;

            const std::string hash = ComputeHashInternal(fullPath, HashUtils::Algorithm::SHA256);
            if (hash != normalizedHash) {
                return true;
            }

            if (auto file = InspectFileUnlocked(*m_impl, fullPath); file.has_value()) {
                matches.push_back(std::move(*file));
            }
            return matches.size() < effectiveMaxResults;
        }, &error);

    return matches;
}

std::vector<FileEntry> FileInspector::FindByName(
    std::wstring_view rootPath,
    std::wstring_view pattern,
    const bool recursive,
    const uint32_t maxResults) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire) || pattern.empty()) {
        return {};
    }

    const auto normalizedPath = NormalizeAndValidatePath(*m_impl, rootPath);
    if (!normalizedPath.has_value()) {
        return {};
    }

    const uint32_t effectiveMaxResults = std::min<uint32_t>(maxResults == 0 ? 1U : maxResults, 1000U);
    FileUtils::WalkOptions options{};
    options.recursive = recursive;
    options.includeDirs = true;
    options.followReparsePoints = false;
    options.maxDepth = recursive ? 8U : 0U;

    std::vector<FileEntry> matches;
    matches.reserve(effectiveMaxResults);

    uint32_t scanned = 0;
    FileUtils::Error error{};
    (void)FileUtils::WalkDirectory(*normalizedPath, options,
        [&](const std::wstring& fullPath, const WIN32_FIND_DATAW&) {
            if (matches.size() >= effectiveMaxResults || scanned >= kMaxWalkResults) {
                return false;
            }
            ++scanned;

            const std::wstring name = LeafName(fullPath);
            if (!WildcardMatch(name, pattern)) {
                return true;
            }

            FileUtils::FileStat stat{};
            FileUtils::Error statError{};
            if (!FileUtils::Stat(fullPath, stat, &statError)) {
                return true;
            }

            matches.push_back(MakeFileEntry(fullPath, stat));
            return matches.size() < effectiveMaxResults;
        }, &error);

    return matches;
}

std::vector<FileEntry> FileInspector::GetRecentlyModifiedFiles(
    std::wstring_view rootPath,
    const uint32_t hours,
    const uint32_t maxResults) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        return {};
    }

    const auto normalizedPath = NormalizeAndValidatePath(*m_impl, rootPath);
    if (!normalizedPath.has_value()) {
        return {};
    }

    const auto threshold = std::chrono::system_clock::now() - std::chrono::hours(hours == 0 ? 1U : hours);
    const uint32_t effectiveMaxResults = std::min<uint32_t>(maxResults == 0 ? 1U : maxResults, 1000U);

    FileUtils::WalkOptions options{};
    options.recursive = true;
    options.includeDirs = false;
    options.followReparsePoints = false;
    options.maxDepth = 8;

    std::vector<FileEntry> matches;
    matches.reserve(effectiveMaxResults);

    uint32_t scanned = 0;
    FileUtils::Error error{};
    (void)FileUtils::WalkDirectory(*normalizedPath, options,
        [&](const std::wstring& fullPath, const WIN32_FIND_DATAW&) {
            if (scanned >= kMaxWalkResults) {
                return false;
            }
            ++scanned;

            FileUtils::FileStat stat{};
            FileUtils::Error statError{};
            if (!FileUtils::Stat(fullPath, stat, &statError) || stat.isDirectory) {
                return true;
            }

            const auto modified = FileTimeToSystemTime(stat.lastWrite);
            if (modified < threshold) {
                return true;
            }

            matches.push_back(MakeFileEntry(fullPath, stat));
            return true;
        }, &error);

    std::ranges::sort(matches, [](const auto& left, const auto& right) {
        return left.modifiedAt > right.modifiedAt;
    });
    if (matches.size() > effectiveMaxResults) {
        matches.resize(effectiveMaxResults);
    }

    return matches;
}

} // namespace ShadowStrike::Products::PhantomEDR::LiveResponse
