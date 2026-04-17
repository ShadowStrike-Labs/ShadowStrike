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

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::LiveResponse {

class RegistryInspectorImpl;

class RegistryInspector final {
public:
    [[nodiscard]] static RegistryInspector& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::optional<RegistryKeySnapshot> BrowseKey(std::wstring_view fullPath);

    struct SearchResult {
        std::wstring keyPath;
        std::wstring valueName;
        std::string dataPreview;
        uint32_t valueType = 0;
    };

    [[nodiscard]] std::vector<SearchResult> SearchValues(
        std::wstring_view rootPath,
        std::wstring_view pattern,
        uint32_t maxDepth = 5,
        uint32_t maxResults = 1000);

    struct AutoRunEntry {
        std::wstring location;
        std::wstring name;
        std::wstring value;
        std::wstring type;
    };

    [[nodiscard]] std::vector<AutoRunEntry> GetAutoRunEntries();

    [[nodiscard]] std::vector<RegistryKeySnapshot> TakeSnapshot(
        std::wstring_view rootPath,
        uint32_t maxDepth = 3);

    [[nodiscard]] std::vector<RegistryDiffEntry> CompareSnapshots(
        const std::vector<RegistryKeySnapshot>& before,
        const std::vector<RegistryKeySnapshot>& after);

private:
    RegistryInspector();
    ~RegistryInspector();

    RegistryInspector(const RegistryInspector&) = delete;
    RegistryInspector& operator=(const RegistryInspector&) = delete;

    std::unique_ptr<RegistryInspectorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::LiveResponse
