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
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

class LateralMovementDetectorImpl;

class LateralMovementDetector final {
public:
    [[nodiscard]] static LateralMovementDetector& Instance() {
        static LateralMovementDetector instance;
        return instance;
    }

    [[nodiscard]] bool Initialize();
    void Shutdown();

    [[nodiscard]] std::optional<LateralMovementEvent> AnalyzeConnection(const NetworkConnection& connection);
    [[nodiscard]] std::vector<LateralMovementEvent> GetDetections(size_t limit = 100) const;
    [[nodiscard]] std::vector<LateralMovementChain> GetLateralChains(size_t limit = 50) const;
    [[nodiscard]] LateralMovementStatistics GetStatistics() const;

    LateralMovementDetector(const LateralMovementDetector&) = delete;
    LateralMovementDetector& operator=(const LateralMovementDetector&) = delete;
    LateralMovementDetector(LateralMovementDetector&&) = delete;
    LateralMovementDetector& operator=(LateralMovementDetector&&) = delete;

    ~LateralMovementDetector();

private:
    LateralMovementDetector();

    std::unique_ptr<LateralMovementDetectorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
