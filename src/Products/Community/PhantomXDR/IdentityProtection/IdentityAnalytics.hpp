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

#include "Products/Community/PhantomXDR/IdentityProtection/IdentityTypes.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::IdentityProtection {

class IdentityAnalyticsImpl;

class IdentityAnalytics final {
public:
    [[nodiscard]] static IdentityAnalytics& Instance();

    [[nodiscard]] bool Initialize(const std::wstring& databasePath = L"", uint32_t baselineLearningDays = 7);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool UpdateProfile(std::wstring_view userName = L"");
    [[nodiscard]] std::vector<IdentityAlert> AnalyzeLogon(const LogonEvent& logon);
    [[nodiscard]] std::optional<UserBehaviorProfile> GetUserProfile(std::wstring_view userName) const;
    [[nodiscard]] std::vector<UserBehaviorProfile> GetHighRiskUsers(double minimumRiskScore = 70.0, size_t limit = 50) const;
    [[nodiscard]] std::vector<IdentityAlert> GetAnomalies(size_t limit = 100) const;
    [[nodiscard]] IdentityAnalyticsStatistics GetStatistics() const;

private:
    IdentityAnalytics();
    ~IdentityAnalytics();

    IdentityAnalytics(const IdentityAnalytics&) = delete;
    IdentityAnalytics& operator=(const IdentityAnalytics&) = delete;
    IdentityAnalytics(IdentityAnalytics&&) = delete;
    IdentityAnalytics& operator=(IdentityAnalytics&&) = delete;

    std::unique_ptr<IdentityAnalyticsImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::IdentityProtection
