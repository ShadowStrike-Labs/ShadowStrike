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
/*
 * ShadowStrike NGAV - Enterprise C++ Implementation
 *
 * Component: PerformanceProfiler
 * Description: High-performance low-overhead profiler for system metrics and code timing.
 * Standards: C++20, PIMPL, Singleton, Thread-Safe
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <optional>
#include <span>
#include <atomic>
#include <filesystem>

// Forward decls
namespace nlohmann { class json; }

namespace ShadowStrike {
namespace Performance {

    namespace fs = std::filesystem;

    struct MetricSnapshot {
        std::string name;
        uint64_t durationNs;
        uint64_t cpuCycles;
        uint64_t memoryUsageBytes;
        uint64_t threadId;
        uint64_t timestamp;
    };

    struct SystemResourceUsage {
        double processCpuUsagePercent;
        uint64_t workingSetBytes;
        uint64_t privateBytes;
        uint64_t readTransferCount;
        uint64_t writeTransferCount;
        uint64_t pageFaultCount;

        [[nodiscard]] std::string ToJson() const;
    };

    class PerformanceProfiler final {
    public:
        // Singleton Access
        [[nodiscard]] static PerformanceProfiler& Instance() noexcept;

        // Deleted lifecycle for Singleton
        PerformanceProfiler(const PerformanceProfiler&) = delete;
        PerformanceProfiler& operator=(const PerformanceProfiler&) = delete;
        PerformanceProfiler(PerformanceProfiler&&) = delete;
        PerformanceProfiler& operator=(PerformanceProfiler&&) = delete;

        // Session Management
        void StartSession(const std::string& sessionName);
        void EndSession();
        [[nodiscard]] bool IsSessionActive() const noexcept;

        // Profiling Control
        void SetEnabled(bool enabled) noexcept;
        [[nodiscard]] bool IsEnabled() const noexcept;

        // Measurement Methods
        void StartProfile(const std::string& name);
        void StopProfile(const std::string& name);

        // Metrics Retrieval
        [[nodiscard]] SystemResourceUsage GetResourceUsage() const;
        [[nodiscard]] std::string GenerateReport() const;
        [[nodiscard]] bool SaveReport(const fs::path& filepath) const;
        [[nodiscard]] double GetAverageExecutionTimeMs(const std::string& name) const;

        // Self-test
        [[nodiscard]] bool SelfTest();

    private:
        PerformanceProfiler();
        ~PerformanceProfiler();

        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

    // RAII Helper for Scoped Profiling
    class ScopedProfile final {
    public:
        explicit ScopedProfile(std::string name);
        ~ScopedProfile();

        ScopedProfile(const ScopedProfile&) = delete;
        ScopedProfile& operator=(const ScopedProfile&) = delete;
        ScopedProfile(ScopedProfile&&) = delete;
        ScopedProfile& operator=(ScopedProfile&&) = delete;

    private:
        std::string m_name;
    };

} // namespace Performance
} // namespace ShadowStrike
