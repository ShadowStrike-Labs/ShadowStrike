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

#include "Products/Community/PhantomEDR/ThreatHunting/ThreatHuntingTypes.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

class HuntQueryEngineImpl;

class HuntQueryEngine final {
public:
    [[nodiscard]] static HuntQueryEngine& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] HuntResult ExecuteQuery(const HuntQuery& query);
    [[nodiscard]] HuntResult ExecuteRawSQL(std::string_view sql, uint32_t maxResults = 10000);
    [[nodiscard]] uint64_t CountMatches(const HuntQuery& query);
    [[nodiscard]] std::vector<std::string> GetAvailableFields();

private:
    HuntQueryEngine();
    ~HuntQueryEngine();

    HuntQueryEngine(const HuntQueryEngine&) = delete;
    HuntQueryEngine& operator=(const HuntQueryEngine&) = delete;

    std::unique_ptr<HuntQueryEngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
