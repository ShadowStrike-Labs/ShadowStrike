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
 *              Internal dev/diagnostic tool — not shipped as a customer feature, but
 *              held to enterprise quality standards for reliable performance analysis.
 * Standards: C++20, PIMPL, Singleton, Thread-Safe
 */

#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <filesystem>

// Forward decls
namespace nlohmann { class json; }

namespace ShadowStrike {
namespace Performance {

    namespace fs = std::filesystem;

    struct MetricSnapshot {
        std::string name;
        uint64_t durationNs{0};
        uint64_t cpuCycles{0};
        uint64_t memoryUsageBytes{0};
        uint64_t threadId{0};
        uint64_t timestamp{0};
    };

    struct SystemResourceUsage {
        double processCpuUsagePercent{0.0};
        uint64_t workingSetBytes{0};
        uint64_t privateBytes{0};
        uint64_t readTransferCount{0};
        uint64_t writeTransferCount{0};
        uint64_t pageFaultCount{0};

        [[nodiscard]] std::string ToJson() const;
    };

    class PerformanceProfiler final {
    public:
        [[nodiscard]] static PerformanceProfiler& Instance() noexcept;

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

        // Management
        void ClearHistory() noexcept;
        [[nodiscard]] size_t GetActiveProfileCount() const noexcept;

        // Self-test
        [[nodiscard]] bool SelfTest();

    private:
        PerformanceProfiler();
        ~PerformanceProfiler();

        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

    // RAII helper — must only be used as a stack-local variable, never as a static.
    class ScopedProfile final {
    public:
        explicit ScopedProfile(std::string name) noexcept;
        ~ScopedProfile() noexcept;

        ScopedProfile(const ScopedProfile&) = delete;
        ScopedProfile& operator=(const ScopedProfile&) = delete;
        ScopedProfile(ScopedProfile&&) = delete;
        ScopedProfile& operator=(ScopedProfile&&) = delete;

    private:
        std::string m_name;
        bool m_active{false};
    };

} // namespace Performance
} // namespace ShadowStrike
