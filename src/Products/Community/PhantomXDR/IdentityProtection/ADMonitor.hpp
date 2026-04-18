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

class ADMonitorImpl;

class ADMonitor final {
public:
    [[nodiscard]] static ADMonitor& Instance();

    [[nodiscard]] bool Initialize(const std::wstring& databasePath = L"");
    void Shutdown();

    [[nodiscard]] bool StartMonitoring();
    void StopMonitoring();

    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] bool IsMonitoring() const noexcept;

    [[nodiscard]] std::vector<LogonEvent> GetRecentLogons(size_t limit = 100, bool successfulOnly = false) const;
    [[nodiscard]] std::vector<LogonEvent> GetFailedLogons(size_t limit = 100, std::wstring_view sourceIP = L"") const;
    [[nodiscard]] std::vector<GroupChangeEvent> GetGroupChanges(size_t limit = 100, std::wstring_view targetUser = L"") const;
    [[nodiscard]] std::vector<IdentityAlert> GetAlerts(size_t limit = 100, std::optional<IdentityThreat> threat = std::nullopt) const;
    [[nodiscard]] ADMonitorStatistics GetStatistics() const;

private:
    ADMonitor();
    ~ADMonitor();

    ADMonitor(const ADMonitor&) = delete;
    ADMonitor& operator=(const ADMonitor&) = delete;
    ADMonitor(ADMonitor&&) = delete;
    ADMonitor& operator=(ADMonitor&&) = delete;

    std::unique_ptr<ADMonitorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::IdentityProtection
