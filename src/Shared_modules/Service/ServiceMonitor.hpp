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

#include <memory>
#include <string>
#include <chrono>
#include <atomic>
#include <optional>

namespace ShadowStrike {
    namespace Service {

        /**
         * @brief Structure holding current service health statistics
         */
        struct ServiceHealthStats {
            double cpuUsagePercent{0.0};
            uint64_t memoryUsageBytes{0};
            uint64_t handleCount{0};
            uint64_t threadCount{0};
            uint64_t uptimeSeconds{0};
            bool isHealthy{true};
            std::string statusMessage;

            [[nodiscard]] std::string ToJson() const;
        };

        /**
         * @brief Service Health Monitoring and Resource Tracking
         *
         * Implements Singleton pattern.
         * Thread-safe.
         * Uses PIMPL for ABI stability.
         */
        class ServiceMonitor final {
        public:
            /**
             * @brief Get the Singleton instance
             * @return Reference to the ServiceMonitor
             */
            [[nodiscard]] static ServiceMonitor& Instance();

            // Deleted copy/move operations
            ServiceMonitor(const ServiceMonitor&) = delete;
            ServiceMonitor& operator=(const ServiceMonitor&) = delete;
            ServiceMonitor(ServiceMonitor&&) = delete;
            ServiceMonitor& operator=(ServiceMonitor&&) = delete;

            /**
             * @brief Starts the monitoring thread
             * @return true if started successfully, false otherwise
             */
            [[nodiscard]] bool StartMonitoring();

            /**
             * @brief Stops the monitoring thread
             */
            void StopMonitoring();

            /**
             * @brief Updates the heartbeat timestamp
             * Call this from the main service loop to prevent hang detection
             */
            void UpdateHeartbeat();

            /**
             * @brief Get current resource usage and health stats
             * @return ServiceHealthStats structure
             */
            [[nodiscard]] ServiceHealthStats GetCurrentStats() const;

            /**
             * @brief Quick check if service is healthy
             * @return true if healthy, false if resource limits exceeded or hung
             */
            [[nodiscard]] bool IsHealthy() const;

            /**
             * @brief Get full diagnostic report in JSON format
             * @return JSON string
             */
            [[nodiscard]] std::string GetDiagnosticsJson() const;

            // Configuration
            void SetMaxMemoryLimit(uint64_t bytes);
            void SetMaxCpuLimit(double percent);
            void SetHeartbeatTimeout(std::chrono::milliseconds timeout);

        private:
            ServiceMonitor();
            ~ServiceMonitor();

            class ServiceMonitorImpl;
            std::unique_ptr<ServiceMonitorImpl> m_impl;
        };

    }
}
