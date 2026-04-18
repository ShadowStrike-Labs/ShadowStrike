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

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::EmailThreat {

class PhishingCorrelatorImpl;

class PhishingCorrelator final {
public:
    [[nodiscard]] static PhishingCorrelator& Instance() {
        static PhishingCorrelator instance;
        return instance;
    }

    PhishingCorrelator();
    ~PhishingCorrelator();

    PhishingCorrelator(const PhishingCorrelator&) = delete;
    PhishingCorrelator& operator=(const PhishingCorrelator&) = delete;
    PhishingCorrelator(PhishingCorrelator&&) = delete;
    PhishingCorrelator& operator=(PhishingCorrelator&&) = delete;

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] PhishingCorrelation CorrelateEmail(const EmailAnalysisResult& analysisResult);
    [[nodiscard]] std::vector<PhishingCorrelation> GetCorrelations(std::size_t limit = 100) const;
    [[nodiscard]] std::vector<CorrelationTimelineEvent> GetAttackTimeline(std::string_view messageId) const;
    [[nodiscard]] PhishingCorrelationStatistics GetStatistics() const noexcept;

private:
    std::unique_ptr<PhishingCorrelatorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::EmailThreat
