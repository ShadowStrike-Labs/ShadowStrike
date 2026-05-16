#include "pch.h"
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
#include "ServiceMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"

#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>

// Link with Psapi.lib
#pragma comment(lib, "Psapi.lib")

namespace ShadowStrike {
    namespace Service {

        namespace {
            constexpr const wchar_t* kServiceMonitorLogCategory = L"ServiceMonitor";
        }

        // ------------------------------------------------------------------------------------------------
        // Implementation Class
        // ------------------------------------------------------------------------------------------------

        class ServiceMonitor::ServiceMonitorImpl {
        public:
            ServiceMonitorImpl();
            ~ServiceMonitorImpl();

            bool Start();
            void Stop();
            void UpdateHeartbeat();

            ServiceHealthStats GetStats() const;
            bool IsHealthy() const;
            std::string GetDiagnosticsJson() const;

            void SetMaxMemoryLimit(uint64_t bytes);
            void SetMaxCpuLimit(double percent);
            void SetHeartbeatTimeout(std::chrono::milliseconds timeout);

        private:
            void MonitorLoop();
            void CollectMetrics();
            double CalculateCpuUsage();

            // Threading
            std::thread m_monitorThread;
            std::atomic<bool> m_isRunning{false};
            std::atomic<bool> m_stopRequested{false};
            mutable std::shared_mutex m_statsMutex;

            // Interruptible sleep: lets Stop() wake the monitor thread
            // immediately instead of waiting up to one poll quantum.
            std::mutex m_sleepMutex;
            std::condition_variable m_sleepCv;

            // Configuration
            std::atomic<uint64_t> m_maxMemoryBytes{1024 * 1024 * 512}; // 512 MB default
            std::atomic<double> m_maxCpuPercent{25.0};                 // 25% default
            // Heartbeat timeout in milliseconds (atomic for lock-free reads
            // from the monitor thread while a config thread updates it).
            std::atomic<int64_t> m_heartbeatTimeoutMs{30000};

            // State (guarded by m_statsMutex unless noted)
            std::chrono::steady_clock::time_point m_lastHeartbeat;
            std::chrono::steady_clock::time_point m_startTime;
            ServiceHealthStats m_currentStats;

            // CPU Calculation helpers (touched only by the monitor thread)
            ULARGE_INTEGER m_lastCpuSysTime{};
            ULARGE_INTEGER m_lastCpuUserTime{};
            ULARGE_INTEGER m_lastSysCpuTime{};
            ULARGE_INTEGER m_lastUserCpuTime{};
            bool m_firstCpuSample{true};
        };

        // ------------------------------------------------------------------------------------------------
        // ServiceHealthStats Implementation
        // ------------------------------------------------------------------------------------------------

        std::string ServiceHealthStats::ToJson() const {
            try {
                nlohmann::json j;
                j["cpuUsagePercent"] = cpuUsagePercent;
                j["memoryUsageBytes"] = memoryUsageBytes;
                j["handleCount"] = handleCount;
                j["threadCount"] = threadCount;
                j["uptimeSeconds"] = uptimeSeconds;
                j["isHealthy"] = isHealthy;
                j["statusMessage"] = statusMessage;
                return j.dump();
            } catch (...) {
                return "{}";
            }
        }

        // ------------------------------------------------------------------------------------------------
        // ServiceMonitorImpl Implementation
        // ------------------------------------------------------------------------------------------------

        ServiceMonitor::ServiceMonitorImpl::ServiceMonitorImpl() {
            m_startTime = std::chrono::steady_clock::now();
            m_lastHeartbeat = std::chrono::steady_clock::now();

            // Initialize stats
            m_currentStats.isHealthy = true;
            m_currentStats.statusMessage = "Initializing";
        }

        ServiceMonitor::ServiceMonitorImpl::~ServiceMonitorImpl() {
            Stop();
        }

        bool ServiceMonitor::ServiceMonitorImpl::Start() {
            if (m_isRunning.exchange(true)) {
                return true; // Already running
            }

            m_stopRequested = false;
            {
                std::unique_lock lock(m_statsMutex);
                m_lastHeartbeat = std::chrono::steady_clock::now();
            }

            try {
                m_monitorThread = std::thread(&ServiceMonitorImpl::MonitorLoop, this);
                SS_LOG_INFO(kServiceMonitorLogCategory, L"Monitoring thread started");
                return true;
            } catch (const std::exception& e) {
                SS_LOG_FATAL(kServiceMonitorLogCategory, L"Failed to start monitoring thread: %hs", e.what());
                m_isRunning = false;
                return false;
            }
        }

        void ServiceMonitor::ServiceMonitorImpl::Stop() {
            if (!m_isRunning.exchange(false)) {
                return;
            }

            m_stopRequested = true;
            // Wake the monitor thread out of its interruptible sleep so the
            // shutdown path doesn't have to wait for a full poll quantum.
            {
                std::lock_guard sleepLock(m_sleepMutex);
            }
            m_sleepCv.notify_all();

            if (m_monitorThread.joinable()) {
                try {
                    m_monitorThread.join();
                } catch (const std::system_error& e) {
                    SS_LOG_ERROR(kServiceMonitorLogCategory,
                        L"Monitor thread join failed: %hs", e.what());
                }
            }
            SS_LOG_INFO(kServiceMonitorLogCategory, L"Monitoring thread stopped");
        }

        void ServiceMonitor::ServiceMonitorImpl::UpdateHeartbeat() {
            std::unique_lock lock(m_statsMutex);
            m_lastHeartbeat = std::chrono::steady_clock::now();
        }

        ServiceHealthStats ServiceMonitor::ServiceMonitorImpl::GetStats() const {
            std::shared_lock lock(m_statsMutex);
            return m_currentStats;
        }

        bool ServiceMonitor::ServiceMonitorImpl::IsHealthy() const {
            std::shared_lock lock(m_statsMutex);
            return m_currentStats.isHealthy;
        }

        std::string ServiceMonitor::ServiceMonitorImpl::GetDiagnosticsJson() const {
            std::shared_lock lock(m_statsMutex);

            try {
                nlohmann::json j;
                j["stats"] = nlohmann::json::parse(m_currentStats.ToJson());

                auto now = std::chrono::steady_clock::now();
                auto heartbeatAge = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastHeartbeat).count();

                j["diagnostics"] = {
                    {"heartbeatAgeMs", heartbeatAge},
                    {"uptimeTotalSeconds", std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime).count()},
                    {"limits", {
                        {"maxMemoryBytes", m_maxMemoryBytes.load()},
                        {"maxCpuPercent", m_maxCpuPercent.load()},
                        {"heartbeatTimeoutMs", m_heartbeatTimeoutMs.load(std::memory_order_acquire)}
                    }}
                };

                return j.dump();
            } catch (const std::exception& e) {
                SS_LOG_ERROR(kServiceMonitorLogCategory, L"Failed to generate diagnostics JSON: %hs", e.what());
                return "{}";
            }
        }

        void ServiceMonitor::ServiceMonitorImpl::SetMaxMemoryLimit(uint64_t bytes) {
            m_maxMemoryBytes = bytes;
            SS_LOG_INFO(kServiceMonitorLogCategory, L"Memory limit set to %llu bytes",
                static_cast<unsigned long long>(bytes));
        }

        void ServiceMonitor::ServiceMonitorImpl::SetMaxCpuLimit(double percent) {
            m_maxCpuPercent = percent;
            SS_LOG_INFO(kServiceMonitorLogCategory, L"CPU limit set to %.2f%%", percent);
        }

        void ServiceMonitor::ServiceMonitorImpl::SetHeartbeatTimeout(std::chrono::milliseconds timeout) {
            if (timeout <= std::chrono::milliseconds::zero()) {
                SS_LOG_WARN(kServiceMonitorLogCategory,
                    L"Refusing non-positive heartbeat timeout (%lld ms); keeping previous value.",
                    static_cast<long long>(timeout.count()));
                return;
            }
            m_heartbeatTimeoutMs.store(timeout.count(), std::memory_order_release);
        }

        void ServiceMonitor::ServiceMonitorImpl::MonitorLoop() {
            using namespace std::chrono_literals;
            // Bounded polling interval — the inner sleep is interruptible via
            // m_sleepCv, so Stop() returns promptly even under a long sleep.
            constexpr auto kPollInterval = 1000ms;

            while (!m_stopRequested.load(std::memory_order_acquire)) {
                try {
                    CollectMetrics();
                } catch (const std::exception& e) {
                    // Swallow but log — a transient OS API failure must NOT
                    // tear down the monitor thread silently. Health visibility
                    // is the whole point of this subsystem.
                    SS_LOG_ERROR(kServiceMonitorLogCategory,
                        L"CollectMetrics threw: %hs", e.what());
                } catch (...) {
                    SS_LOG_ERROR(kServiceMonitorLogCategory,
                        L"CollectMetrics threw an unknown exception");
                }

                std::unique_lock sleepLock(m_sleepMutex);
                m_sleepCv.wait_for(sleepLock, kPollInterval, [this] {
                    return m_stopRequested.load(std::memory_order_acquire);
                });
            }
        }

        double ServiceMonitor::ServiceMonitorImpl::CalculateCpuUsage() {
            FILETIME ftime;
            ULARGE_INTEGER now;
            double percent = 0.0;

            GetSystemTimeAsFileTime(&ftime);
            memcpy(&now, &ftime, sizeof(FILETIME));

            HANDLE hProcess = GetCurrentProcess();
            FILETIME ftCreation, ftExit, ftKernel, ftUser;

            if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                ULARGE_INTEGER uKernel{}, uUser{};
                uKernel.LowPart = ftKernel.dwLowDateTime;
                uKernel.HighPart = ftKernel.dwHighDateTime;
                uUser.LowPart = ftUser.dwLowDateTime;
                uUser.HighPart = ftUser.dwHighDateTime;

                if (!m_firstCpuSample) {
                    // Wall-clock delta (100-ns ticks).
                    const ULONGLONG sysDiff =
                        (now.QuadPart >= m_lastSysCpuTime.QuadPart)
                            ? (now.QuadPart - m_lastSysCpuTime.QuadPart) : 0ULL;

                    // Process CPU time delta (kernel + user, 100-ns ticks).
                    const ULONGLONG kernelDelta =
                        (uKernel.QuadPart >= m_lastCpuSysTime.QuadPart)
                            ? (uKernel.QuadPart - m_lastCpuSysTime.QuadPart) : 0ULL;
                    const ULONGLONG userDelta =
                        (uUser.QuadPart >= m_lastCpuUserTime.QuadPart)
                            ? (uUser.QuadPart - m_lastCpuUserTime.QuadPart) : 0ULL;
                    const ULONGLONG processDelta = kernelDelta + userDelta;

                    if (sysDiff > 0) {
                        SYSTEM_INFO sysInfo;
                        GetSystemInfo(&sysInfo);
                        const DWORD numProc = sysInfo.dwNumberOfProcessors
                                                  ? sysInfo.dwNumberOfProcessors : 1u;
                        // (process time delta) / (wall-clock delta * numProc) * 100
                        percent = static_cast<double>(processDelta) * 100.0
                                / (static_cast<double>(sysDiff)
                                   * static_cast<double>(numProc));
                        if (percent < 0.0)   percent = 0.0;
                        if (percent > 100.0) percent = 100.0;
                    }
                }

                m_lastSysCpuTime = now;
                m_lastCpuSysTime = uKernel;
                m_lastCpuUserTime = uUser;
                m_firstCpuSample = false;
            }

            return percent;
        }

        void ServiceMonitor::ServiceMonitorImpl::CollectMetrics() {
            ServiceHealthStats newStats;

            // 1. Memory and Handles
            PROCESS_MEMORY_COUNTERS_EX pmc{};
            if (GetProcessMemoryInfo(GetCurrentProcess(),
                                     reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                                     sizeof(pmc))) {
                newStats.memoryUsageBytes = pmc.PrivateUsage;
            }

            DWORD handleCount = 0;
            if (GetProcessHandleCount(GetCurrentProcess(), &handleCount)) {
                newStats.handleCount = handleCount;
            }

            // 2. CPU
            newStats.cpuUsagePercent = CalculateCpuUsage();

            // 3. Uptime — read m_startTime under the stats lock (it is set in
            // the constructor and never reassigned, but read here for parity
            // with the protected access discipline).
            const auto now = std::chrono::steady_clock::now();
            std::chrono::steady_clock::time_point startTimeSnapshot;
            std::chrono::steady_clock::time_point heartbeatSnapshot;
            {
                std::shared_lock lock(m_statsMutex);
                startTimeSnapshot = m_startTime;
                heartbeatSnapshot = m_lastHeartbeat;
            }
            newStats.uptimeSeconds =
                std::chrono::duration_cast<std::chrono::seconds>(now - startTimeSnapshot).count();

            // 4. Thread count via ToolHelp32 snapshot — wrap the snapshot
            // handle in a RAII guard so an exception while iterating cannot
            // leak the kernel handle.
            {
                const DWORD pid = GetCurrentProcessId();
                HANDLE rawSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (rawSnap != INVALID_HANDLE_VALUE) {
                    struct SnapDeleter {
                        void operator()(HANDLE h) const noexcept {
                            if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
                        }
                    };
                    std::unique_ptr<void, SnapDeleter> hSnap(rawSnap);

                    uint64_t count = 0;
                    THREADENTRY32 te{};
                    te.dwSize = sizeof(THREADENTRY32);
                    if (Thread32First(hSnap.get(), &te)) {
                        do {
                            if (te.th32OwnerProcessID == pid) {
                                ++count;
                            }
                            te.dwSize = sizeof(THREADENTRY32);
                        } while (Thread32Next(hSnap.get(), &te));
                    }
                    newStats.threadCount = count;
                }
            }

            // 5. Health Check
            bool healthy = true;
            std::stringstream status;
            status << "OK";

            // Check Limits
            const uint64_t memLimit = m_maxMemoryBytes.load(std::memory_order_acquire);
            if (memLimit != 0 && newStats.memoryUsageBytes > memLimit) {
                healthy = false;
                status.str("");
                status << "High Memory Usage: " << (newStats.memoryUsageBytes / 1024 / 1024) << "MB";
                SS_LOG_WARN(kServiceMonitorLogCategory, L"Memory limit exceeded: %llu bytes",
                    static_cast<unsigned long long>(newStats.memoryUsageBytes));
            }

            const double cpuLimit = m_maxCpuPercent.load(std::memory_order_acquire);
            if (newStats.cpuUsagePercent > cpuLimit) {
                // CPU spikes are normal during scans; only flag sustained overuse
                SS_LOG_WARN(kServiceMonitorLogCategory, L"CPU usage %.1f%% exceeds threshold %.1f%%",
                    newStats.cpuUsagePercent, cpuLimit);
            }

            // Check Hang (Heartbeat)
            const auto timeSinceLastHeartbeat =
                std::chrono::duration_cast<std::chrono::milliseconds>(now - heartbeatSnapshot);
            const std::chrono::milliseconds heartbeatTimeout{
                m_heartbeatTimeoutMs.load(std::memory_order_acquire)};
            if (timeSinceLastHeartbeat > heartbeatTimeout) {
                healthy = false;
                status.str("");
                status << "Service Hung (No Heartbeat for " << timeSinceLastHeartbeat.count() << "ms)";
                SS_LOG_ERROR(kServiceMonitorLogCategory, L"Hang detected: no heartbeat for %lld ms",
                    static_cast<long long>(timeSinceLastHeartbeat.count()));
            }

            newStats.isHealthy = healthy;
            newStats.statusMessage = status.str();

            // Update stats
            {
                std::unique_lock lock(m_statsMutex);
                m_currentStats = newStats;
            }
        }

        // ------------------------------------------------------------------------------------------------
        // ServiceMonitor Wrapper
        // ------------------------------------------------------------------------------------------------

        ServiceMonitor& ServiceMonitor::Instance() {
            static ServiceMonitor instance;
            return instance;
        }

        ServiceMonitor::ServiceMonitor() : m_impl(std::make_unique<ServiceMonitorImpl>()) {
        }

        ServiceMonitor::~ServiceMonitor() = default;

        bool ServiceMonitor::StartMonitoring() {
            return m_impl->Start();
        }

        void ServiceMonitor::StopMonitoring() {
            m_impl->Stop();
        }

        void ServiceMonitor::UpdateHeartbeat() {
            m_impl->UpdateHeartbeat();
        }

        ServiceHealthStats ServiceMonitor::GetCurrentStats() const {
            return m_impl->GetStats();
        }

        bool ServiceMonitor::IsHealthy() const {
            return m_impl->IsHealthy();
        }

        std::string ServiceMonitor::GetDiagnosticsJson() const {
            return m_impl->GetDiagnosticsJson();
        }

        void ServiceMonitor::SetMaxMemoryLimit(uint64_t bytes) {
            m_impl->SetMaxMemoryLimit(bytes);
        }

        void ServiceMonitor::SetMaxCpuLimit(double percent) {
            m_impl->SetMaxCpuLimit(percent);
        }

        void ServiceMonitor::SetHeartbeatTimeout(std::chrono::milliseconds timeout) {
            m_impl->SetHeartbeatTimeout(timeout);
        }

    }
}
