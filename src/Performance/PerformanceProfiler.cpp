#include "PerformanceProfiler.hpp"
#include "../Utils/Logger.hpp"
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
#include <nlohmann/json.hpp>
#include <iostream>
#include <intrin.h>

#pragma comment(lib, "psapi.lib")

using json = nlohmann::json;

namespace ShadowStrike {
namespace Performance {

    // Implementation of SystemResourceUsage::ToJson
    std::string SystemResourceUsage::ToJson() const {
        return json{
            {"cpuUsagePercent", processCpuUsagePercent},
            {"workingSetBytes", workingSetBytes},
            {"privateBytes", privateBytes},
            {"readTransferCount", readTransferCount},
            {"writeTransferCount", writeTransferCount},
            {"pageFaultCount", pageFaultCount}
        }.dump();
    }

    // -------------------------------------------------------------------------
    // PerformanceProfiler::Impl
    // -------------------------------------------------------------------------

    class PerformanceProfiler::Impl {
    public:
        Impl() : m_enabled(true), m_sessionActive(false) {
            // Initialize CPU usage calculation
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            m_numProcessors = sysInfo.dwNumberOfProcessors;
        }

        void StartSession(const std::string& name) {
            std::unique_lock lock(m_mutex);
            m_sessionName = name;
            m_sessionActive = true;
            m_snapshots.clear();
            m_startTime = std::chrono::steady_clock::now();
            m_stats.clear();
            Logger::Info("Performance Session Started: {}", name);
        }

        void EndSession() {
            std::unique_lock lock(m_mutex);
            m_sessionActive = false;
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - m_startTime).count();
            Logger::Info("Performance Session Ended. Duration: {}ms. Total Samples: {}",
                duration, m_snapshots.size());
        }

        void StartProfile(const std::string& name) {
            if (!m_enabled) return;

            auto threadId = std::this_thread::get_id();

            // Key by thread + name to allow simple recursion handling
            ActiveKey key{threadId, name};
            StartData startData{
                std::chrono::high_resolution_clock::now(),
                GetCPUCycles()
            };

            std::lock_guard lock(m_activeProfilesMutex);
            m_activeProfiles[key] = startData;
        }

        void StopProfile(const std::string& name) {
            if (!m_enabled) return;

            auto endTp = std::chrono::high_resolution_clock::now();
            uint64_t endCycles = GetCPUCycles();
            auto threadId = std::this_thread::get_id();

            ActiveKey key{threadId, name};
            StartData startData;

            {
                std::lock_guard lock(m_activeProfilesMutex);
                auto it = m_activeProfiles.find(key);
                if (it == m_activeProfiles.end()) return;
                startData = it->second;
                m_activeProfiles.erase(it);
            }

            // Calculate duration
            uint64_t durationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                endTp - startData.tp).count();
            uint64_t cpuCycles = (endCycles > startData.cycles) ? (endCycles - startData.cycles) : 0;

            // Store result
            std::unique_lock lock(m_mutex);

            if (m_sessionActive) {
                m_snapshots.push_back({
                    name,
                    durationNs,
                    cpuCycles,
                    0,
                    std::hash<std::thread::id>{}(threadId),
                    static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count())
                });
            }

            // Update stats
            auto& stat = m_stats[name];
            stat.count++;
            stat.totalTimeNs += durationNs;
        }

        SystemResourceUsage GetResourceUsage() const {
            SystemResourceUsage usage{};

            // Memory
            PROCESS_MEMORY_COUNTERS_EX pmc;
            if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                usage.workingSetBytes = pmc.WorkingSetSize;
                usage.privateBytes = pmc.PrivateUsage;
                usage.pageFaultCount = pmc.PageFaultCount;
            }

            // IO
            IO_COUNTERS ioCounters;
            if (GetProcessIoCounters(GetCurrentProcess(), &ioCounters)) {
                usage.readTransferCount = ioCounters.ReadTransferCount;
                usage.writeTransferCount = ioCounters.WriteTransferCount;
            }

            // CPU
            std::lock_guard lock(m_cpuMutex);
            usage.processCpuUsagePercent = CalculateCpuUsage();

            return usage;
        }

        std::string GenerateReport() const {
            std::shared_lock lock(m_mutex);
            json report;
            report["session"] = m_sessionName;
            report["total_samples"] = m_snapshots.size();

            // Aggregate stats
            json statsObj;
            for (const auto& [name, stat] : m_stats) {
                statsObj[name] = {
                    {"count", stat.count},
                    {"total_ns", stat.totalTimeNs},
                    {"avg_ms", (stat.count > 0) ? (double)stat.totalTimeNs / stat.count / 1000000.0 : 0.0}
                };
            }
            report["statistics"] = statsObj;

            // Recent snapshots (limit to last 1000)
            json events = json::array();
            size_t startIdx = (m_snapshots.size() > 1000) ? m_snapshots.size() - 1000 : 0;
            for (size_t i = startIdx; i < m_snapshots.size(); ++i) {
                const auto& s = m_snapshots[i];
                events.push_back({
                    {"name", s.name},
                    {"dur_ns", s.durationNs},
                    {"cpu", s.cpuCycles},
                    {"tid", s.threadId}
                });
            }
            report["events"] = events;

            return report.dump(4);
        }

        bool SaveReport(const fs::path& filepath) const {
            try {
                std::string content = GenerateReport();
                if (filepath.has_parent_path()) {
                    fs::create_directories(filepath.parent_path());
                }
                std::ofstream ofs(filepath);
                if (!ofs.is_open()) return false;
                ofs << content;
                return true;
            } catch (...) {
                return false;
            }
        }

        double GetAverageExecutionTimeMs(const std::string& name) const {
            std::shared_lock lock(m_mutex);
            auto it = m_stats.find(name);
            if (it != m_stats.end() && it->second.count > 0) {
                return (double)it->second.totalTimeNs / it->second.count / 1000000.0;
            }
            return 0.0;
        }

        void SetEnabled(bool enabled) { m_enabled = enabled; }
        bool IsEnabled() const { return m_enabled; }
        bool IsSessionActive() const { return m_sessionActive; }

    private:
        struct ActiveKey {
            std::thread::id threadId;
            std::string name;
            bool operator<(const ActiveKey& other) const {
                if (threadId != other.threadId) return threadId < other.threadId;
                return name < other.name;
            }
        };

        struct StartData {
            std::chrono::high_resolution_clock::time_point tp;
            uint64_t cycles;
        };

        struct StatData {
            uint64_t count{0};
            uint64_t totalTimeNs{0};
        };

        mutable std::shared_mutex m_mutex;
        std::atomic<bool> m_enabled;
        std::atomic<bool> m_sessionActive;
        std::string m_sessionName;
        std::chrono::steady_clock::time_point m_startTime;

        std::vector<MetricSnapshot> m_snapshots;
        mutable std::map<std::string, StatData> m_stats;

        std::mutex m_activeProfilesMutex;
        std::map<ActiveKey, StartData> m_activeProfiles;

        // CPU Usage Tracking
        mutable std::mutex m_cpuMutex;
        mutable ULARGE_INTEGER m_lastCpuTime{0};
        mutable ULARGE_INTEGER m_lastSysCpuTime{0};
        mutable ULARGE_INTEGER m_lastUserCpuTime{0};
        int m_numProcessors;

        uint64_t GetCPUCycles() {
            return __rdtsc();
        }

        double CalculateCpuUsage() const {
            FILETIME ftime, fsys, fuser;
            ULARGE_INTEGER now, sys, user;
            double percent;

            GetSystemTimeAsFileTime(&ftime);
            memcpy(&now, &ftime, sizeof(FILETIME));

            GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser);
            memcpy(&sys, &fsys, sizeof(FILETIME));
            memcpy(&user, &fuser, sizeof(FILETIME));

            if (m_lastCpuTime.QuadPart != 0) {
                ULONGLONG timeDiff = now.QuadPart - m_lastCpuTime.QuadPart;
                ULONGLONG sysDiff = sys.QuadPart - m_lastSysCpuTime.QuadPart;
                ULONGLONG userDiff = user.QuadPart - m_lastUserCpuTime.QuadPart;

                if (timeDiff > 0) {
                    percent = (double)(sysDiff + userDiff) / timeDiff / m_numProcessors * 100.0;
                } else {
                    percent = 0.0;
                }
            } else {
                percent = 0.0;
            }

            m_lastCpuTime = now;
            m_lastSysCpuTime = sys;
            m_lastUserCpuTime = user;

            return percent;
        }
    };

    // -------------------------------------------------------------------------
    // PerformanceProfiler Wrapper
    // -------------------------------------------------------------------------

    PerformanceProfiler& PerformanceProfiler::Instance() noexcept {
        static PerformanceProfiler instance;
        return instance;
    }

    PerformanceProfiler::PerformanceProfiler() : m_impl(std::make_unique<Impl>()) {}
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

    bool PerformanceProfiler::SelfTest() {
        // Quick self test
        StartSession("SelfTest");
        {
            ScopedProfile p("TestProfile");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        EndSession();

        auto report = GenerateReport();

        if (report.find("TestProfile") == std::string::npos) {
            Logger::Error("PerformanceProfiler SelfTest Failed: Profile not found");
            return false;
        }

        Logger::Info("PerformanceProfiler SelfTest Passed");
        return true;
    }

    // -------------------------------------------------------------------------
    // ScopedProfile
    // -------------------------------------------------------------------------

    ScopedProfile::ScopedProfile(std::string name) : m_name(std::move(name)) {
        PerformanceProfiler::Instance().StartProfile(m_name);
    }

    ScopedProfile::~ScopedProfile() {
        PerformanceProfiler::Instance().StopProfile(m_name);
    }

} // namespace Performance
} // namespace ShadowStrike
