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

#include "EmailTypes.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::EmailThreat {

class EmailAnalyzerImpl;

class EmailAnalyzer final {
public:
    [[nodiscard]] static EmailAnalyzer& Instance() {
        static EmailAnalyzer instance;
        return instance;
    }

    EmailAnalyzer();
    ~EmailAnalyzer();

    EmailAnalyzer(const EmailAnalyzer&) = delete;
    EmailAnalyzer& operator=(const EmailAnalyzer&) = delete;
    EmailAnalyzer(EmailAnalyzer&&) = delete;
    EmailAnalyzer& operator=(EmailAnalyzer&&) = delete;

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] EmailAnalysisResult ScanEmailFile(const std::filesystem::path& emailPath);
    [[nodiscard]] std::vector<EmailAnalysisResult> ScanDirectory(const std::filesystem::path& directoryPath,
                                                                 bool recursive = true);
    [[nodiscard]] std::optional<EmailAnalysisResult> GetScanResult(std::string_view messageId) const;
    [[nodiscard]] std::vector<EmailAnalysisResult> GetScanHistory(std::size_t limit = 100) const;
    [[nodiscard]] EmailAnalyzerStatistics GetStatistics() const noexcept;

private:
    std::unique_ptr<EmailAnalyzerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::EmailThreat
