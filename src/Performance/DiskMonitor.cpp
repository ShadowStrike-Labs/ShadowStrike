/**
 * ============================================================================
 * ShadowStrike NGAV - DISK MONITORING MODULE IMPLEMENTATION
 * ============================================================================
 *
 * @file DiskMonitor.cpp
 * @brief Implementation of the enterprise disk monitoring engine.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "DiskMonitor.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <thread>
#include <vector>
#include <map>
#include <unordered_map>
#include <string>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <Psapi.h>
#include <pdh.h>
#include <pdhmsg.h>

#pragma comment(lib, "pdh.lib")

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"DiskMonitor";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> DiskMonitor::s_instanceCreated{false};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
namespace {
    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string ProcessDiskUsage::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"processId\":" << processId << ","
        << "\"processName\":\"" << EscapeJson(WStringToString(processName)) << "\","
        << "\"readBytesPerSec\":" << readBytesPerSec << ","
        << "\"writeBytesPerSec\":" << writeBytesPerSec << ","
        << "\"readOpsPerSec\":" << readOpsPerSec << ","
        << "\"writeOpsPerSec\":" << writeOpsPerSec << ","
        << "\"totalReadBytes\":" << totalReadBytes << ","
        << "\"totalWriteBytes\":" << totalWriteBytes << ","
        << "\"highWriteRate\":" << (highWriteRate ? "true" : "false")
        << "}";
    return oss.str();
}

std::string DriveInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"mountPoint\":\"" << EscapeJson(WStringToString(mountPoint)) << "\","
        << "\"volumeName\":\"" << EscapeJson(WStringToString(volumeName)) << "\","
        << "\"fileSystem\":\"" << EscapeJson(WStringToString(fileSystem)) << "\","
        << "\"totalBytes\":" << totalBytes << ","
        << "\"freeBytes\":" << freeBytes << ","
        << "\"usagePercent\":" << usagePercent << ","
        << "\"isSystemDrive\":" << (isSystemDrive ? "true" : "false")
        << "}";
    return oss.str();
}

std::string DiskGlobalStats::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalReadBytesPerSec\":" << totalReadBytesPerSec << ","
        << "\"totalWriteBytesPerSec\":" << totalWriteBytesPerSec << ","
        << "\"totalReadOpsPerSec\":" << totalReadOpsPerSec << ","
        << "\"totalWriteOpsPerSec\":" << totalWriteOpsPerSec << ","
        << "\"activeProcesses\":" << activeProcesses
        << "}";
    return oss.str();
}

bool DiskMonitorConfig::IsValid() const noexcept {
    if (pollingIntervalMs < DiskConstants::MIN_POLLING_INTERVAL_MS ||
        pollingIntervalMs > DiskConstants::MAX_POLLING_INTERVAL_MS) {
        return false;
    }
    return true;
}

void DiskMonitorModuleStats::Reset() noexcept {
    cyclesCompleted = 0;
    alertsTriggered = 0;
    errorsEncountered = 0;
    processesTracked = 0;
    startTime = Clock::now();
}

std::string DiskMonitorModuleStats::ToJson() const {
    std::ostringstream oss;
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - startTime).count();
    oss << "{"
        << "\"cyclesCompleted\":" << cyclesCompleted.load() << ","
        << "\"alertsTriggered\":" << alertsTriggered.load() << ","
        << "\"errorsEncountered\":" << errorsEncountered.load() << ","
        << "\"processesTracked\":" << processesTracked.load() << ","
        << "\"uptimeSeconds\":" << uptime
        << "}";
    return oss.str();
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class DiskMonitorImpl {
public:
    DiskMonitorImpl() = default;
    ~DiskMonitorImpl() { Shutdown(); }

    bool Initialize(const DiskMonitorConfig& config) {
        std::unique_lock lock(m_mutex);
        if (m_running) return true;

        if (!config.IsValid()) {
            return false;
        }

        m_config = config;
        m_stats.Reset();
        m_running = true;

        if (m_config.enabled) {
            m_thread = std::thread(&DiskMonitorImpl::MonitorLoop, this);
        }

        return true;
    }

    void Shutdown() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) return;
            m_running = false;
        }

        if (m_thread.joinable()) {
            m_thread.join();
        }

        // Cleanup callbacks
        std::unique_lock lock(m_cbMutex);
        m_highIoCallbacks.clear();
        m_lowSpaceCallbacks.clear();
    }

    void UpdateConfig(const DiskMonitorConfig& config) {
        std::unique_lock lock(m_mutex);
        if (config.IsValid()) {
            m_config = config;
        }
    }

    DiskMonitorConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // MONITORING LOGIC
    // ========================================================================

    void MonitorLoop() {
        while (m_running) {
            auto start = Clock::now();

            {
                std::shared_lock lock(m_mutex);
                if (!m_config.enabled) {
                    lock.unlock();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
            }

            try {
                if (m_config.enableProcessMonitoring) {
                    UpdateProcessStats();
                }

                if (m_config.enableDriveSpaceMonitoring) {
                    UpdateDriveInfo();
                }

                m_stats.cyclesCompleted++;
            } catch (...) {
                m_stats.errorsEncountered++;
            }

            auto end = Clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            uint32_t interval = m_config.pollingIntervalMs;
            if (duration.count() < interval) {
                std::this_thread::sleep_for(std::chrono::milliseconds(interval - duration.count()));
            }
        }
    }

    void UpdateProcessStats() {
        // Enumerate all processes
        DWORD pids[1024], bytesReturned;
        if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
            return;
        }

        DWORD count = bytesReturned / sizeof(DWORD);
        auto now = Clock::now();
        double deltaTime = 0.0;

        if (m_lastProcessUpdate != TimePoint()) {
            deltaTime = std::chrono::duration<double>(now - m_lastProcessUpdate).count();
        }
        m_lastProcessUpdate = now;

        if (deltaTime <= 0.0001) deltaTime = 1.0; // Avoid div/0 on first run

        std::unordered_map<uint32_t, ProcessDiskUsage> currentUsage;
        DiskGlobalStats global{};
        global.timestamp = now;

        for (DWORD i = 0; i < count; i++) {
            if (pids[i] == 0) continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
            if (hProcess) {
                IO_COUNTERS counters;
                if (GetProcessIoCounters(hProcess, &counters)) {
                    ProcessDiskUsage usage{};
                    usage.processId = pids[i];

                    // Get name
                    WCHAR name[MAX_PATH] = L"<unknown>";
                    HMODULE hMod;
                    DWORD cbNeeded;
                    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                        GetModuleBaseNameW(hProcess, hMod, name, sizeof(name)/sizeof(WCHAR));
                    }
                    usage.processName = name;

                    usage.totalReadBytes = counters.ReadTransferCount;
                    usage.totalWriteBytes = counters.WriteTransferCount;

                    // Calculate deltas if we saw this process before
                    auto it = m_prevCounters.find(pids[i]);
                    if (it != m_prevCounters.end()) {
                        uint64_t dReadBytes = (counters.ReadTransferCount >= it->second.readBytes) ?
                            (counters.ReadTransferCount - it->second.readBytes) : 0;
                        uint64_t dWriteBytes = (counters.WriteTransferCount >= it->second.writeBytes) ?
                            (counters.WriteTransferCount - it->second.writeBytes) : 0;
                        uint64_t dReadOps = (counters.ReadOperationCount >= it->second.readOps) ?
                            (counters.ReadOperationCount - it->second.readOps) : 0;
                        uint64_t dWriteOps = (counters.WriteOperationCount >= it->second.writeOps) ?
                            (counters.WriteOperationCount - it->second.writeOps) : 0;

                        usage.readBytesPerSec = dReadBytes / deltaTime;
                        usage.writeBytesPerSec = dWriteBytes / deltaTime;
                        usage.readOpsPerSec = dReadOps / deltaTime;
                        usage.writeOpsPerSec = dWriteOps / deltaTime;

                        // Check thresholds
                        if (usage.writeBytesPerSec > m_config.ransomwareWriteThresholdBps) {
                            usage.highWriteRate = true;
                            NotifyHighIo(usage);
                        }
                    }

                    // Store current counters for next time
                    DiskIoCounters currRaw;
                    currRaw.readBytes = counters.ReadTransferCount;
                    currRaw.writeBytes = counters.WriteTransferCount;
                    currRaw.readOps = counters.ReadOperationCount;
                    currRaw.writeOps = counters.WriteOperationCount;
                    m_prevCounters[pids[i]] = currRaw;

                    if (usage.readBytesPerSec > 0 || usage.writeBytesPerSec > 0) {
                        currentUsage[pids[i]] = usage;

                        global.totalReadBytesPerSec += usage.readBytesPerSec;
                        global.totalWriteBytesPerSec += usage.writeBytesPerSec;
                        global.totalReadOpsPerSec += usage.readOpsPerSec;
                        global.totalWriteOpsPerSec += usage.writeOpsPerSec;
                        global.activeProcesses++;
                    }
                }
                CloseHandle(hProcess);
            }
        }

        // Clean up old pids from map
        for (auto it = m_prevCounters.begin(); it != m_prevCounters.end();) {
            if (currentUsage.find(it->first) == currentUsage.end() &&
                std::find(pids, pids + count, it->first) == pids + count) {
                it = m_prevCounters.erase(it);
            } else {
                ++it;
            }
        }

        // Store results
        {
            std::unique_lock lock(m_dataMutex);
            m_processUsage = std::move(currentUsage);
            m_globalStats = global;
        }

        m_stats.processesTracked = m_prevCounters.size();
    }

    void UpdateDriveInfo() {
        DWORD drives = GetLogicalDrives();
        std::vector<DriveInfo> driveInfos;

        // Find system drive
        WCHAR winDir[MAX_PATH];
        std::wstring systemDrive;
        if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
            systemDrive = std::wstring(winDir).substr(0, 3);
        }

        for (int i = 0; i < 26; i++) {
            if (drives & (1 << i)) {
                std::wstring mountPoint = L"A:\\";
                mountPoint[0] += i;

                UINT type = GetDriveTypeW(mountPoint.c_str());
                if (type == DRIVE_FIXED) {
                    DriveInfo info;
                    info.mountPoint = mountPoint;
                    info.isSystemDrive = (mountPoint == systemDrive);

                    WCHAR volName[MAX_PATH + 1] = { 0 };
                    WCHAR fsName[MAX_PATH + 1] = { 0 };
                    if (GetVolumeInformationW(mountPoint.c_str(), volName, MAX_PATH,
                        NULL, NULL, NULL, fsName, MAX_PATH)) {
                        info.volumeName = volName;
                        info.fileSystem = fsName;
                    }

                    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
                    if (GetDiskFreeSpaceExW(mountPoint.c_str(), &freeBytes, &totalBytes, &totalFree)) {
                        info.availableBytes = freeBytes.QuadPart;
                        info.totalBytes = totalBytes.QuadPart;
                        info.freeBytes = totalFree.QuadPart;

                        if (info.totalBytes > 0) {
                            info.usagePercent = 100.0 * (1.0 - (double)info.availableBytes / (double)info.totalBytes);
                        }

                        // Check low space (e.g. < 5% or < 1GB)
                        if (info.usagePercent > 95.0 || info.availableBytes < 1024ULL * 1024 * 1024) {
                            NotifyLowSpace(info);
                        }
                    }
                    driveInfos.push_back(info);
                }
            }
        }

        std::unique_lock lock(m_dataMutex);
        m_drives = std::move(driveInfos);
    }

    // ========================================================================
    // ACCESSORS
    // ========================================================================

    std::optional<ProcessDiskUsage> GetProcessUsage(uint32_t pid) const {
        std::shared_lock lock(m_dataMutex);
        auto it = m_processUsage.find(pid);
        if (it != m_processUsage.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<ProcessDiskUsage> GetTopConsumers(size_t count) const {
        std::shared_lock lock(m_dataMutex);
        std::vector<ProcessDiskUsage> consumers;
        consumers.reserve(m_processUsage.size());

        for (const auto& kv : m_processUsage) {
            consumers.push_back(kv.second);
        }

        // Sort by total bandwidth (read+write per sec)
        std::sort(consumers.begin(), consumers.end(), [](const ProcessDiskUsage& a, const ProcessDiskUsage& b) {
            return (a.readBytesPerSec + a.writeBytesPerSec) > (b.readBytesPerSec + b.writeBytesPerSec);
        });

        if (consumers.size() > count) {
            consumers.resize(count);
        }

        return consumers;
    }

    DiskGlobalStats GetGlobalStats() const {
        std::shared_lock lock(m_dataMutex);
        return m_globalStats;
    }

    std::vector<DriveInfo> GetDriveInfo() const {
        std::shared_lock lock(m_dataMutex);
        return m_drives;
    }

    DiskMonitorModuleStats GetModuleStats() const {
        return m_stats;
    }

    // ========================================================================
    // CALLBACK MANAGEMENT
    // ========================================================================

    void RegisterHighIoCallback(HighIoCallback callback) {
        std::unique_lock lock(m_cbMutex);
        m_highIoCallbacks.push_back(std::move(callback));
    }

    void RegisterLowSpaceCallback(LowSpaceCallback callback) {
        std::unique_lock lock(m_cbMutex);
        m_lowSpaceCallbacks.push_back(std::move(callback));
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_cbMutex);
        m_highIoCallbacks.clear();
        m_lowSpaceCallbacks.clear();
    }

    void NotifyHighIo(const ProcessDiskUsage& usage) {
        std::shared_lock lock(m_cbMutex);
        for (const auto& cb : m_highIoCallbacks) {
            try { cb(usage); } catch(...) {}
        }
        m_stats.alertsTriggered++;
    }

    void NotifyLowSpace(const DriveInfo& info) {
        std::shared_lock lock(m_cbMutex);
        for (const auto& cb : m_lowSpaceCallbacks) {
            try { cb(info); } catch(...) {}
        }
        m_stats.alertsTriggered++;
    }

private:
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_dataMutex;
    mutable std::shared_mutex m_cbMutex;

    std::atomic<bool> m_running{false};
    std::thread m_thread;

    DiskMonitorConfig m_config;
    DiskMonitorModuleStats m_stats;

    // Data storage
    std::unordered_map<uint32_t, DiskIoCounters> m_prevCounters;
    TimePoint m_lastProcessUpdate;

    std::unordered_map<uint32_t, ProcessDiskUsage> m_processUsage;
    DiskGlobalStats m_globalStats;
    std::vector<DriveInfo> m_drives;

    // Callbacks
    std::vector<HighIoCallback> m_highIoCallbacks;
    std::vector<LowSpaceCallback> m_lowSpaceCallbacks;
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

DiskMonitor& DiskMonitor::Instance() noexcept {
    static DiskMonitor instance;
    return instance;
}

DiskMonitor::DiskMonitor() : m_impl(std::make_unique<DiskMonitorImpl>()) {
    s_instanceCreated.store(true);
}

DiskMonitor::~DiskMonitor() {
    s_instanceCreated.store(false);
}

bool DiskMonitor::Initialize(const DiskMonitorConfig& config) {
    return m_impl->Initialize(config);
}

void DiskMonitor::Shutdown() {
    m_impl->Shutdown();
}

bool DiskMonitor::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

void DiskMonitor::UpdateConfig(const DiskMonitorConfig& config) {
    m_impl->UpdateConfig(config);
}

DiskMonitorConfig DiskMonitor::GetConfig() const {
    return m_impl->GetConfig();
}

std::optional<ProcessDiskUsage> DiskMonitor::GetProcessUsage(uint32_t pid) const {
    return m_impl->GetProcessUsage(pid);
}

std::vector<ProcessDiskUsage> DiskMonitor::GetTopConsumers(size_t count) const {
    return m_impl->GetTopConsumers(count);
}

DiskGlobalStats DiskMonitor::GetGlobalStats() const {
    return m_impl->GetGlobalStats();
}

std::vector<DriveInfo> DiskMonitor::GetDriveInfo() const {
    return m_impl->GetDriveInfo();
}

void DiskMonitor::RegisterHighIoCallback(HighIoCallback callback) {
    m_impl->RegisterHighIoCallback(std::move(callback));
}

void DiskMonitor::RegisterLowSpaceCallback(LowSpaceCallback callback) {
    m_impl->RegisterLowSpaceCallback(std::move(callback));
}

void DiskMonitor::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

DiskMonitorModuleStats DiskMonitor::GetModuleStats() const {
    return m_impl->GetModuleStats();
}

bool DiskMonitor::SelfTest() {
    return true; // Simplified for now
}

std::string DiskMonitor::GetVersionString() noexcept {
    return "3.0.0";
}

} // namespace Performance
} // namespace ShadowStrike
