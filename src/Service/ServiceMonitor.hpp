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
