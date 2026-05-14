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
#include "pch.h"
#include "PerformanceProfiler.hpp"
#include "../../Utils/Logger.hpp"

#include <Windows.h>
#include <Psapi.h>

#include <map>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <deque>
#include <numeric>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <format>
#include <intrin.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "psapi.lib")

namespace nl = nlohmann;

namespace ShadowStrike {
namespace Performance {

    namespace Logger {
        template <typename... Args>
        void Error(std::format_string<Args...> fmt, Args&&... args) {
            const auto message = std::format(fmt, std::forward<Args>(args)...);
            SS_LOG_ERROR(L"PerformanceProfiler", L"%hs", message.c_str());
        }

        template <typename... Args>
        void Warn(std::format_string<Args...> fmt, Args&&... args) {
            const auto message = std::format(fmt, std::forward<Args>(args)...);
            SS_LOG_WARN(L"PerformanceProfiler", L"%hs", message.c_str());
        }

        template <typename... Args>
        void Info(std::format_string<Args...> fmt, Args&&... args) {
            const auto message = std::format(fmt, std::forward<Args>(args)...);
            SS_LOG_INFO(L"PerformanceProfiler", L"%hs", message.c_str());
        }

        template <typename... Args>
        void Debug(std::format_string<Args...> fmt, Args&&... args) {
            const auto message = std::format(fmt, std::forward<Args>(args)...);
            SS_LOG_DEBUG(L"PerformanceProfiler", L"%hs", message.c_str());
        }
    }

    // -------------------------------------------------------------------------
    // Module-scoped hard limits — prevents unbounded memory growth
    // -------------------------------------------------------------------------
    static constexpr size_t kMaxProfileNameLength = 256;
    static constexpr size_t kMaxActiveProfiles    = 10'000;
    static constexpr size_t kMaxSnapshotHistory   = 100'000;
    static constexpr size_t kMaxStatsEntries      = 10'000;
    static constexpr size_t kMaxReportEvents      = 1'000;

    // -------------------------------------------------------------------------
    // SystemResourceUsage::ToJson
    // -------------------------------------------------------------------------
    std::string SystemResourceUsage::ToJson() const {
        try {
            return nl::json{
                {"cpuUsagePercent",    processCpuUsagePercent},
                {"workingSetBytes",    workingSetBytes},
                {"privateBytes",       privateBytes},
                {"readTransferCount",  readTransferCount},
                {"writeTransferCount", writeTransferCount},
                {"pageFaultCount",     pageFaultCount}
            }.dump();
        } catch (const std::exception& ex) {
            Logger::Error("SystemResourceUsage::ToJson serialization failed: {}", ex.what());
            return "{}";
        }
    }

    // -------------------------------------------------------------------------
    // PerformanceProfiler::Impl
    // -------------------------------------------------------------------------
    class PerformanceProfiler::Impl {
    public:
        Impl() : m_enabled(true), m_sessionActive(false), m_numProcessors(1) {
            SYSTEM_INFO sysInfo{};
            GetSystemInfo(&sysInfo);
            m_numProcessors = static_cast<int>(sysInfo.dwNumberOfProcessors);
            if (m_numProcessors <= 0) {
                m_numProcessors = 1;
            }
        }

        // -- Session Management -----------------------------------------------

        void StartSession(const std::string& name) {
            if (name.empty()) {
                Logger::Warn("PerformanceProfiler::StartSession called with empty name — ignoring");
                return;
            }

            std::unique_lock lock(m_mutex);

            if (m_sessionActive.load(std::memory_order_relaxed)) {
                Logger::Warn("PerformanceProfiler::StartSession called while '{}' is active — ending previous session",
                    m_sessionName);
                EndSessionLocked();
            }

            // Cap the session name to bound memory and log inputs that exceed
            // the cap so the caller can see why their string was truncated.
            if (name.size() > kMaxProfileNameLength) {
                Logger::Warn("PerformanceProfiler::StartSession name length {} exceeds limit {} — truncating",
                    name.size(), kMaxProfileNameLength);
            }

            m_sessionName = name.substr(0, kMaxProfileNameLength);
            m_snapshots.clear();
            m_stats.clear();
            {
                std::lock_guard activeLock(m_activeProfilesMutex);
                m_activeProfiles.clear();
            }
            m_startTime = std::chrono::steady_clock::now();
            m_sessionActive.store(true, std::memory_order_release);

            Logger::Info("Performance session started: '{}'", m_sessionName);
        }

        void EndSession() {
            std::unique_lock lock(m_mutex);

            if (!m_sessionActive.load(std::memory_order_relaxed)) {
                Logger::Debug("PerformanceProfiler::EndSession called with no active session — ignoring");
                return;
            }

            EndSessionLocked();
        }

        // -- Profiling --------------------------------------------------------

        void StartProfile(const std::string& name) {
            if (!m_enabled.load(std::memory_order_acquire)) return;

            if (name.empty() || name.size() > kMaxProfileNameLength) {
                Logger::Warn("PerformanceProfiler::StartProfile invalid name "
                    "(empty or exceeds {} chars)", kMaxProfileNameLength);
                return;
            }

            // Capture timing BEFORE acquiring lock for accuracy
            const auto now    = std::chrono::high_resolution_clock::now();
            const uint64_t cycles = GetCPUCycles();

            const auto threadId = std::this_thread::get_id();
            ActiveKey key{threadId, name};
            StartData startData{now, cycles};

            std::lock_guard lock(m_activeProfilesMutex);

            if (m_activeProfiles.size() >= kMaxActiveProfiles) {
                Logger::Warn("PerformanceProfiler::StartProfile max active profiles ({}) reached "
                    "— dropping '{}'", kMaxActiveProfiles, name);
                return;
            }

            if (m_activeProfiles.contains(key)) {
                Logger::Debug("PerformanceProfiler::StartProfile overwriting '{}' on same thread "
                    "(re-entrant or missing StopProfile)", name);
            }

            m_activeProfiles[key] = startData;
        }

        void StopProfile(const std::string& name) {
            if (name.empty() || name.size() > kMaxProfileNameLength) return;

            // Capture timing BEFORE acquiring lock for accuracy
            const auto endTp       = std::chrono::high_resolution_clock::now();
            const uint64_t endCycles = GetCPUCycles();
            const auto threadId    = std::this_thread::get_id();

            ActiveKey key{threadId, name};
            StartData startData{};

            {
                std::lock_guard lock(m_activeProfilesMutex);
                auto it = m_activeProfiles.find(key);
                if (it == m_activeProfiles.end()) {
                    Logger::Debug("PerformanceProfiler::StopProfile '{}' without matching "
                        "StartProfile on this thread", name);
                    return;
                }
                startData = it->second;
                m_activeProfiles.erase(it);
            }

            // Calculate metrics (overflow-safe: chrono duration_cast is well-defined)
            const uint64_t durationNs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    endTp - startData.tp).count());

            // RDTSC may decrease on core migration — clamp to 0
            const uint64_t cpuCycles = (endCycles >= startData.cycles)
                ? (endCycles - startData.cycles) : 0;

            const uint64_t hashedThreadId = std::hash<std::thread::id>{}(threadId);
            const uint64_t timestamp = static_cast<uint64_t>(
                std::chrono::system_clock::now().time_since_epoch().count());

            // Best-effort snapshot of the process working-set at sample time so
            // MetricSnapshot::memoryUsageBytes (a public field of the dev API)
            // is populated rather than always zero. The query is only issued
            // when a session is active so the non-recording fast path keeps its
            // current overhead profile.
            uint64_t memoryAtStop = 0;
            const bool sessionActive = m_sessionActive.load(std::memory_order_relaxed);
            if (sessionActive) {
                PROCESS_MEMORY_COUNTERS_EX pmcSnap{};
                pmcSnap.cb = sizeof(pmcSnap);
                if (GetProcessMemoryInfo(GetCurrentProcess(),
                        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmcSnap), sizeof(pmcSnap))) {
                    memoryAtStop = pmcSnap.WorkingSetSize;
                }
            }

            std::unique_lock lock(m_mutex);

            // Record snapshot only during an active session
            if (m_sessionActive.load(std::memory_order_relaxed)) {
                while (m_snapshots.size() >= kMaxSnapshotHistory) {
                    m_snapshots.pop_front();
                }
                m_snapshots.push_back(MetricSnapshot{
                    name, durationNs, cpuCycles, memoryAtStop, hashedThreadId, timestamp
                });
            }

            // Always accumulate aggregate stats (bounded)
            if (m_stats.size() < kMaxStatsEntries || m_stats.contains(name)) {
                auto& stat = m_stats[name];
                stat.count++;
                stat.totalTimeNs += durationNs;
                stat.minTimeNs = std::min(stat.minTimeNs, durationNs);
                stat.maxTimeNs = std::max(stat.maxTimeNs, durationNs);
            }
        }

        // -- Metrics Retrieval ------------------------------------------------

        [[nodiscard]] SystemResourceUsage GetResourceUsage() const {
            SystemResourceUsage usage{};

            PROCESS_MEMORY_COUNTERS_EX pmc{};
            pmc.cb = sizeof(pmc);
            const HANDLE hProcess = GetCurrentProcess();

            if (GetProcessMemoryInfo(hProcess,
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                usage.workingSetBytes = pmc.WorkingSetSize;
                usage.privateBytes    = pmc.PrivateUsage;
                usage.pageFaultCount  = pmc.PageFaultCount;
            }

            IO_COUNTERS ioCounters{};
            if (GetProcessIoCounters(hProcess, &ioCounters)) {
                usage.readTransferCount  = ioCounters.ReadTransferCount;
                usage.writeTransferCount = ioCounters.WriteTransferCount;
            }

            {
                std::lock_guard lock(m_cpuMutex);
                usage.processCpuUsagePercent = CalculateCpuUsage();
            }

            return usage;
        }

        [[nodiscard]] std::string GenerateReport() const {
            std::shared_lock lock(m_mutex);
            return GenerateReportLocked();
        }

        [[nodiscard]] bool SaveReport(const fs::path& filepath) const {
            if (filepath.empty()) {
                Logger::Error("PerformanceProfiler::SaveReport called with empty path");
                return false;
            }

            // Reject device and extended-length paths
            const std::wstring pathStr = filepath.wstring();
            if (pathStr.starts_with(L"\\\\.\\") || pathStr.starts_with(L"\\\\?\\")) {
                Logger::Error("PerformanceProfiler::SaveReport rejecting device/extended path");
                return false;
            }

            // Warn on unexpected extensions
            const auto ext = filepath.extension();
            if (ext != ".json" && ext != ".txt" && ext != ".log") {
                Logger::Warn("PerformanceProfiler::SaveReport unexpected extension '{}'",
                    ext.string());
            }

            try {
                std::string content;
                {
                    std::shared_lock lock(m_mutex);
                    content = GenerateReportLocked();
                }

                if (filepath.has_parent_path() && !filepath.parent_path().empty()) {
                    std::error_code ec;
                    fs::create_directories(filepath.parent_path(), ec);
                    if (ec) {
                        Logger::Error("PerformanceProfiler::SaveReport failed to create "
                            "directories '{}': {}", filepath.parent_path().string(), ec.message());
                        return false;
                    }
                }

                std::ofstream ofs(filepath, std::ios::out | std::ios::trunc);
                if (!ofs.is_open()) {
                    Logger::Error("PerformanceProfiler::SaveReport failed to open '{}'",
                        filepath.string());
                    return false;
                }

                ofs << content;
                ofs.flush();

                if (ofs.fail()) {
                    Logger::Error("PerformanceProfiler::SaveReport write failed for '{}'",
                        filepath.string());
                    return false;
                }

                ofs.close();
                Logger::Info("Performance report saved: '{}'", filepath.string());
                return true;

            } catch (const std::exception& ex) {
                Logger::Error("PerformanceProfiler::SaveReport exception: {}", ex.what());
                return false;
            }
        }

        [[nodiscard]] double GetAverageExecutionTimeMs(const std::string& name) const {
            std::shared_lock lock(m_mutex);
            auto it = m_stats.find(name);
            if (it != m_stats.end() && it->second.count > 0) {
                return static_cast<double>(it->second.totalTimeNs)
                    / static_cast<double>(it->second.count) / 1'000'000.0;
            }
            return 0.0;
        }

        // -- State Accessors --------------------------------------------------

        void SetEnabled(bool enabled) noexcept {
            m_enabled.store(enabled, std::memory_order_release);
        }

        [[nodiscard]] bool IsEnabled() const noexcept {
            return m_enabled.load(std::memory_order_acquire);
        }

        [[nodiscard]] bool IsSessionActive() const noexcept {
            return m_sessionActive.load(std::memory_order_acquire);
        }

        void ClearHistory() noexcept {
            try {
                {
                    std::unique_lock lock(m_mutex);
                    m_snapshots.clear();
                    m_stats.clear();
                }
                {
                    std::lock_guard lock(m_activeProfilesMutex);
                    m_activeProfiles.clear();
                }
            } catch (const std::exception& ex) {
                Logger::Warn("ClearHistory failed to acquire profiler locks: {}", ex.what());
            }
        }

        [[nodiscard]] size_t GetActiveProfileCount() const noexcept {
            try {
                std::lock_guard lock(m_activeProfilesMutex);
                return m_activeProfiles.size();
            } catch (const std::exception& ex) {
                Logger::Warn("GetActiveProfileCount failed to acquire profiler lock: {}", ex.what());
                return 0;
            }
        }

    private:
        // -- Internal Structures ----------------------------------------------

        struct ActiveKey {
            std::thread::id threadId;
            std::string name;

            [[nodiscard]] bool operator<(const ActiveKey& other) const {
                if (threadId != other.threadId) return threadId < other.threadId;
                return name < other.name;
            }
        };

        struct StartData {
            std::chrono::high_resolution_clock::time_point tp{};
            uint64_t cycles{0};
        };

        struct StatData {
            uint64_t count{0};
            uint64_t totalTimeNs{0};
            uint64_t minTimeNs{UINT64_MAX};
            uint64_t maxTimeNs{0};
        };

        // -- Data Members -----------------------------------------------------

        // Main profiling state — guarded by m_mutex
        mutable std::shared_mutex m_mutex;
        std::atomic<bool>  m_enabled;
        std::atomic<bool>  m_sessionActive;
        std::string        m_sessionName;
        std::chrono::steady_clock::time_point m_startTime{};
        std::deque<MetricSnapshot>            m_snapshots;
        std::map<std::string, StatData>       m_stats;

        // Active profiles — separate mutex to reduce contention on the hot path
        mutable std::mutex m_activeProfilesMutex;
        std::map<ActiveKey, StartData> m_activeProfiles;

        // CPU usage tracking — separate mutex for isolated state
        mutable std::mutex m_cpuMutex;
        mutable ULARGE_INTEGER m_lastCpuTime{};
        mutable ULARGE_INTEGER m_lastSysCpuTime{};
        mutable ULARGE_INTEGER m_lastUserCpuTime{};
        int m_numProcessors{1};

        // -- Internal Helpers -------------------------------------------------

        void EndSessionLocked() {
            m_sessionActive.store(false, std::memory_order_release);
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - m_startTime).count();
            Logger::Info("Performance session '{}' ended — duration: {}ms, samples: {}",
                m_sessionName, elapsed, m_snapshots.size());
        }

        // LFENCE before RDTSC serializes the instruction stream for accurate cycle counts.
        // Note: RDTSC is not invariant on all CPUs and may differ across cores; a value
        // of 0 is recorded when core migration is detected (end < start).
        [[nodiscard]] static uint64_t GetCPUCycles() noexcept {
            _mm_lfence();
            return __rdtsc();
        }

        [[nodiscard]] double CalculateCpuUsage() const {
            FILETIME ftNow{};
            FILETIME ftCreation{};
            FILETIME ftExit{};
            FILETIME ftKernel{};
            FILETIME ftUser{};

            GetSystemTimeAsFileTime(&ftNow);

            ULARGE_INTEGER now{};
            now.LowPart  = ftNow.dwLowDateTime;
            now.HighPart = ftNow.dwHighDateTime;

            if (!GetProcessTimes(GetCurrentProcess(),
                    &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                return 0.0;
            }

            ULARGE_INTEGER kernel{};
            kernel.LowPart  = ftKernel.dwLowDateTime;
            kernel.HighPart = ftKernel.dwHighDateTime;

            ULARGE_INTEGER user{};
            user.LowPart  = ftUser.dwLowDateTime;
            user.HighPart = ftUser.dwHighDateTime;

            double percent = 0.0;

            // Wall-clock FILETIME is normally monotonic but may step backward
            // after SetSystemTime / NTP correction. Guard the subtraction so
            // we never feed a wrapped ULONGLONG into the CPU-usage ratio.
            if (m_lastCpuTime.QuadPart != 0 && now.QuadPart > m_lastCpuTime.QuadPart) {
                const ULONGLONG timeDiff = now.QuadPart - m_lastCpuTime.QuadPart;
                // Process kernel/user times are accumulated and should be
                // monotonic, but guard against pathological ordering anyway.
                const ULONGLONG kernelDiff = (kernel.QuadPart >= m_lastSysCpuTime.QuadPart)
                    ? (kernel.QuadPart - m_lastSysCpuTime.QuadPart) : 0;
                const ULONGLONG userDiff   = (user.QuadPart   >= m_lastUserCpuTime.QuadPart)
                    ? (user.QuadPart   - m_lastUserCpuTime.QuadPart)   : 0;
                percent = static_cast<double>(kernelDiff + userDiff)
                    / static_cast<double>(timeDiff)
                    / m_numProcessors * 100.0;
                percent = std::clamp(percent, 0.0, 100.0);
            }

            m_lastCpuTime     = now;
            m_lastSysCpuTime  = kernel;
            m_lastUserCpuTime = user;

            return percent;
        }

        [[nodiscard]] std::string GenerateReportLocked() const {
            try {
                nl::json report;
                report["session"]       = m_sessionName;
                report["total_samples"] = m_snapshots.size();

                if (m_startTime != std::chrono::steady_clock::time_point{}) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - m_startTime).count();
                    report["session_elapsed_ms"] = elapsed;
                }

                nl::json statsObj = nl::json::object();
                for (const auto& [name, stat] : m_stats) {
                    nl::json entry;
                    entry["count"]    = stat.count;
                    entry["total_ns"] = stat.totalTimeNs;
                    entry["avg_ms"]   = (stat.count > 0)
                        ? (static_cast<double>(stat.totalTimeNs)
                            / static_cast<double>(stat.count) / 1'000'000.0)
                        : 0.0;
                    if (stat.count > 0) {
                        entry["min_ns"] = stat.minTimeNs;
                        entry["max_ns"] = stat.maxTimeNs;
                    }
                    statsObj[name] = entry;
                }
                report["statistics"] = statsObj;

                nl::json events = nl::json::array();
                const size_t total    = m_snapshots.size();
                const size_t startIdx = (total > kMaxReportEvents)
                    ? (total - kMaxReportEvents) : 0;

                for (size_t i = startIdx; i < total; ++i) {
                    const auto& s = m_snapshots[i];
                    events.push_back({
                        {"name",   s.name},
                        {"dur_ns", s.durationNs},
                        {"cpu",    s.cpuCycles},
                        {"mem",    s.memoryUsageBytes},
                        {"tid",    s.threadId},
                        {"ts",     s.timestamp}
                    });
                }
                report["events"] = events;

                return report.dump(4);

            } catch (const std::exception& ex) {
                Logger::Error("PerformanceProfiler::GenerateReport serialization failed: {}",
                    ex.what());
                return R"({"error":"report generation failed"})";
            }
        }
    };

    // -------------------------------------------------------------------------
    // PerformanceProfiler — Meyers' Singleton & PIMPL forwarding
    // -------------------------------------------------------------------------

    PerformanceProfiler& PerformanceProfiler::Instance() noexcept {
        static PerformanceProfiler instance;
        return instance;
    }

    PerformanceProfiler::PerformanceProfiler()
        : m_impl(std::make_unique<Impl>()) {}

    PerformanceProfiler::~PerformanceProfiler() = default;

    void PerformanceProfiler::StartSession(const std::string& sessionName) {
        m_impl->StartSession(sessionName);
    }

    void PerformanceProfiler::EndSession() {
        m_impl->EndSession();
    }

    bool PerformanceProfiler::IsSessionActive() const noexcept {
        return m_impl->IsSessionActive();
    }

    void PerformanceProfiler::SetEnabled(bool enabled) noexcept {
        m_impl->SetEnabled(enabled);
    }

    bool PerformanceProfiler::IsEnabled() const noexcept {
        return m_impl->IsEnabled();
    }

    void PerformanceProfiler::StartProfile(const std::string& name) {
        m_impl->StartProfile(name);
    }

    void PerformanceProfiler::StopProfile(const std::string& name) {
        m_impl->StopProfile(name);
    }

    SystemResourceUsage PerformanceProfiler::GetResourceUsage() const {
        return m_impl->GetResourceUsage();
    }

    std::string PerformanceProfiler::GenerateReport() const {
        return m_impl->GenerateReport();
    }

    bool PerformanceProfiler::SaveReport(const fs::path& filepath) const {
        return m_impl->SaveReport(filepath);
    }

    double PerformanceProfiler::GetAverageExecutionTimeMs(const std::string& name) const {
        return m_impl->GetAverageExecutionTimeMs(name);
    }

    void PerformanceProfiler::ClearHistory() noexcept {
        m_impl->ClearHistory();
    }

    size_t PerformanceProfiler::GetActiveProfileCount() const noexcept {
        return m_impl->GetActiveProfileCount();
    }

    bool PerformanceProfiler::SelfTest() {
        const bool wasEnabled = IsEnabled();
        SetEnabled(true);

        if (IsSessionActive()) {
            Logger::Warn("PerformanceProfiler::SelfTest ending active session to run diagnostics");
        }

        StartSession("__SelfTest__");
        {
            ScopedProfile p("SelfTest_Probe");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        const double avgMs      = GetAverageExecutionTimeMs("SelfTest_Probe");
        const std::string report = GenerateReport();
        EndSession();

        SetEnabled(wasEnabled);

        const bool profileFound    = (report.find("SelfTest_Probe") != std::string::npos);
        const bool timingPlausible = (avgMs >= 1.0 && avgMs < 5000.0);

        if (!profileFound) {
            Logger::Error("PerformanceProfiler SelfTest FAILED: profile not found in report");
            return false;
        }

        if (!timingPlausible) {
            Logger::Warn("PerformanceProfiler SelfTest timing suspect (avg={}ms, expected ~10ms)",
                avgMs);
        }

        Logger::Info("PerformanceProfiler SelfTest PASSED (avg={}ms)", avgMs);
        return true;
    }

    // -------------------------------------------------------------------------
    // ScopedProfile — RAII wrapper
    // -------------------------------------------------------------------------

    ScopedProfile::ScopedProfile(std::string name) noexcept
        : m_name(std::move(name)), m_active(false)
    {
        try {
            PerformanceProfiler::Instance().StartProfile(m_name);
            m_active = true;
        } catch (const std::exception& ex) {
            Logger::Warn("ScopedProfile start failed for '{}': {}", m_name, ex.what());
        }
    }

    ScopedProfile::~ScopedProfile() noexcept {
        if (m_active) {
            try {
                PerformanceProfiler::Instance().StopProfile(m_name);
            } catch (const std::exception& ex) {
                Logger::Warn("ScopedProfile stop failed for '{}': {}", m_name, ex.what());
            }
        }
    }

} // namespace Performance
} // namespace ShadowStrike
