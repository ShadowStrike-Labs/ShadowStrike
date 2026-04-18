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

class TLSInspectorImpl;

class TLSInspector final {
public:
    [[nodiscard]] static TLSInspector& Instance() {
        static TLSInspector instance;
        return instance;
    }

    [[nodiscard]] bool Initialize();
    void Shutdown();

    [[nodiscard]] TLSSession InspectSession(const TLSSession& session);
    [[nodiscard]] std::vector<std::string> GetKnownMaliciousJA3() const;
    [[nodiscard]] bool AddJA3Classification(std::string_view ja3Hash, std::string_view classification, std::string_view notes = {});
    [[nodiscard]] std::vector<TLSSession> GetCertAnomalies(size_t limit = 100) const;
    [[nodiscard]] TLSInspectorStatistics GetStatistics() const;

    TLSInspector(const TLSInspector&) = delete;
    TLSInspector& operator=(const TLSInspector&) = delete;
    TLSInspector(TLSInspector&&) = delete;
    TLSInspector& operator=(TLSInspector&&) = delete;

    ~TLSInspector();

private:
    TLSInspector();

    std::unique_ptr<TLSInspectorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
