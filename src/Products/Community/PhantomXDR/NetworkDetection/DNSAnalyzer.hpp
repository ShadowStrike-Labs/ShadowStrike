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

#include "NetworkTypes.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

class DNSAnalyzerImpl;

class DNSAnalyzer final {
public:
    [[nodiscard]] static DNSAnalyzer& Instance() {
        static DNSAnalyzer instance;
        return instance;
    }

    [[nodiscard]] bool Initialize();
    void Shutdown();

    [[nodiscard]] DNSQuery AnalyzeQuery(const DNSQuery& query);
    [[nodiscard]] std::vector<std::string> GetSuspiciousDomains(size_t limit = 100) const;
    [[nodiscard]] std::vector<DNSQuery> GetDGADetections(size_t limit = 100) const;
    [[nodiscard]] std::vector<DNSQuery> GetTunnelingDetections(size_t limit = 100) const;
    [[nodiscard]] bool AddWhitelistDomain(std::string_view domain);
    [[nodiscard]] DNSAnalyzerStatistics GetStatistics() const;

    DNSAnalyzer(const DNSAnalyzer&) = delete;
    DNSAnalyzer& operator=(const DNSAnalyzer&) = delete;
    DNSAnalyzer(DNSAnalyzer&&) = delete;
    DNSAnalyzer& operator=(DNSAnalyzer&&) = delete;

    ~DNSAnalyzer();

private:
    DNSAnalyzer();

    std::unique_ptr<DNSAnalyzerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
