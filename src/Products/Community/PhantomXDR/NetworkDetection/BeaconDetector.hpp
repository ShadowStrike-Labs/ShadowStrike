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
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

class BeaconDetectorImpl;

class BeaconDetector final {
public:
    [[nodiscard]] static BeaconDetector& Instance() {
        static BeaconDetector instance;
        return instance;
    }

    [[nodiscard]] bool Initialize(const BeaconDetectorSettings& settings = {});
    void Shutdown();

    void RecordConnection(const NetworkConnection& connection);
    [[nodiscard]] std::optional<BeaconPattern> AnalyzeDestination(std::string_view destination) const;
    [[nodiscard]] std::vector<BeaconPattern> GetBeaconPatterns(size_t limit = 100) const;
    [[nodiscard]] std::vector<std::string> GetSuspiciousDestinations(size_t limit = 100) const;
    [[nodiscard]] BeaconDetectorStatistics GetStatistics() const;

    BeaconDetector(const BeaconDetector&) = delete;
    BeaconDetector& operator=(const BeaconDetector&) = delete;
    BeaconDetector(BeaconDetector&&) = delete;
    BeaconDetector& operator=(BeaconDetector&&) = delete;

    ~BeaconDetector();

private:
    BeaconDetector();

    std::unique_ptr<BeaconDetectorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
