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
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

class NetworkSensorImpl;

class NetworkSensor final {
public:
    [[nodiscard]] static NetworkSensor& Instance() {
        static NetworkSensor instance;
        return instance;
    }

    [[nodiscard]] bool Initialize(const NetworkSensorSettings& settings = {});
    void Shutdown();

    [[nodiscard]] bool StartCapture();
    void StopCapture();

    [[nodiscard]] std::vector<NetworkConnection> GetActiveConnections() const;
    [[nodiscard]] std::vector<NetworkConnection> GetConnectionHistory(size_t limit = 1000) const;
    [[nodiscard]] NetworkSensorStatistics GetStatistics() const;

    NetworkSensor(const NetworkSensor&) = delete;
    NetworkSensor& operator=(const NetworkSensor&) = delete;
    NetworkSensor(NetworkSensor&&) = delete;
    NetworkSensor& operator=(NetworkSensor&&) = delete;

    ~NetworkSensor();

private:
    NetworkSensor();

    std::unique_ptr<NetworkSensorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
