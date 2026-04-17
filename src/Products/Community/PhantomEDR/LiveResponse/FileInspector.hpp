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

#include "Products/Community/PhantomEDR/LiveResponse/LiveResponseTypes.hpp"

#include "PhantomCore/Utils/HashUtils.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::LiveResponse {

class FileInspectorImpl;

class FileInspector final {
public:
    [[nodiscard]] static FileInspector& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    void SetAllowedRoots(const std::vector<std::wstring>& roots);

    [[nodiscard]] std::vector<FileEntry> ListDirectory(
        std::wstring_view path,
        bool recursive = false,
        uint32_t maxDepth = 3,
        uint32_t maxResults = 10000);

    [[nodiscard]] std::optional<FileEntry> InspectFile(std::wstring_view path);

    [[nodiscard]] std::string ComputeHash(
        std::wstring_view path,
        ShadowStrike::Utils::HashUtils::Algorithm alg = ShadowStrike::Utils::HashUtils::Algorithm::SHA256);

    [[nodiscard]] std::vector<FileTimelineEntry> GetFileTimeline(
        std::wstring_view rootPath,
        std::chrono::system_clock::time_point startTime,
        std::chrono::system_clock::time_point endTime,
        uint32_t maxResults = 5000);

    [[nodiscard]] std::vector<FileEntry> FindByHash(
        std::wstring_view rootPath,
        std::string_view sha256Hash,
        uint32_t maxResults = 100);

    [[nodiscard]] std::vector<FileEntry> FindByName(
        std::wstring_view rootPath,
        std::wstring_view pattern,
        bool recursive = true,
        uint32_t maxResults = 1000);

    [[nodiscard]] std::vector<FileEntry> GetRecentlyModifiedFiles(
        std::wstring_view rootPath,
        uint32_t hours = 24,
        uint32_t maxResults = 1000);

private:
    FileInspector();
    ~FileInspector();

    FileInspector(const FileInspector&) = delete;
    FileInspector& operator=(const FileInspector&) = delete;

    std::unique_ptr<FileInspectorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::LiveResponse
