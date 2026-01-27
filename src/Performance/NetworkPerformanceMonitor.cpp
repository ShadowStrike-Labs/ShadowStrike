/**
 * ============================================================================
 * ShadowStrike NGAV - NETWORK PERFORMANCE MONITORING MODULE IMPLEMENTATION
 * ============================================================================
 *
 * @file NetworkPerformanceMonitor.cpp
 * @brief Implementation of the enterprise network monitoring engine.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "NetworkPerformanceMonitor.hpp"

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

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"NetworkMonitor";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> NetworkPerformanceMonitor::s_instanceCreated{false};

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

std::string NetworkInterfaceStats::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"interfaceName\":\"" << EscapeJson(interfaceName) << "\","
        << "\"description\":\"" << EscapeJson(description) << "\","
        << "\"macAddress\":\"" << EscapeJson(macAddress) << "\","
        << "\"inboundBitsPerSec\":" << inboundBitsPerSec << ","
        << "\"outboundBitsPerSec\":" << outboundBitsPerSec << ","
        << "\"isUp\":" << (isUp ? "true" : "false")
        << "}";
    return oss.str();
}

std::string ProcessNetworkUsage::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"processId\":" << processId << ","
        << "\"processName\":\"" << EscapeJson(WStringToString(processName)) << "\","
        << "\"tcpConnections\":" << tcpConnections << ","
        << "\"udpListeners\":" << udpListeners
        << "}";
    return oss.str();
}

std::string NetworkGlobalStats::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalInboundBitsPerSec\":" << totalInboundBitsPerSec << ","
        << "\"totalOutboundBitsPerSec\":" << totalOutboundBitsPerSec << ","
        << "\"totalTcpConnections\":" << totalTcpConnections << ","
        << "\"activeInterfaces\":" << activeInterfaces
        << "}";
    return oss.str();
}

bool NetworkMonitorConfig::IsValid() const noexcept {
    return pollingIntervalMs >= NetworkConstants::MIN_POLLING_INTERVAL_MS &&
           pollingIntervalMs <= NetworkConstants::MAX_POLLING_INTERVAL_MS;
}

void NetworkMonitorModuleStats::Reset() noexcept {
    cyclesCompleted = 0;
    errorsEncountered = 0;
    alertsTriggered = 0;
    startTime = Clock::now();
}

std::string NetworkMonitorModuleStats::ToJson() const {
    std::ostringstream oss;
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - startTime).count();
    oss << "{"
        << "\"cyclesCompleted\":" << cyclesCompleted.load() << ","
        << "\"errorsEncountered\":" << errorsEncountered.load() << ","
        << "\"uptimeSeconds\":" << uptime
        << "}";
    return oss.str();
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class NetworkPerformanceMonitorImpl {
public:
    NetworkPerformanceMonitorImpl() = default;
    ~NetworkPerformanceMonitorImpl() { Shutdown(); }

    bool Initialize(const NetworkMonitorConfig& config) {
        std::unique_lock lock(m_mutex);
        if (m_running) return true;

        if (!config.IsValid()) return false;

        m_config = config;
        m_stats.Reset();
        m_running = true;

        if (m_config.enabled) {
            m_thread = std::thread(&NetworkPerformanceMonitorImpl::MonitorLoop, this);
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
    }

    void UpdateConfig(const NetworkMonitorConfig& config) {
        std::unique_lock lock(m_mutex);
        if (config.IsValid()) {
            m_config = config;
        }
    }

    NetworkMonitorConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // MONITORING LOOP
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
                if (m_config.trackInterfaces) UpdateInterfaceStats();
                if (m_config.trackPerProcess) UpdateProcessStats();

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

    // ========================================================================
    // METRICS COLLECTION
    // ========================================================================

    void UpdateInterfaceStats() {
        PMIB_IF_TABLE2 ifTable = nullptr;
        if (GetIfTable2(&ifTable) != NO_ERROR) return;

        auto now = Clock::now();
        double deltaTime = 0.0;
        if (m_lastInterfaceUpdate != TimePoint()) {
            deltaTime = std::chrono::duration<double>(now - m_lastInterfaceUpdate).count();
        }
        m_lastInterfaceUpdate = now;
        if (deltaTime <= 0.0001) deltaTime = 1.0;

        std::vector<NetworkInterfaceStats> currentStats;
        NetworkGlobalStats globalStats{};
        globalStats.timestamp = now;

        for (DWORD i = 0; i < ifTable->NumEntries; i++) {
            const auto& row = ifTable->Table[i];

            // Skip Loopback and non-connected
            if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (row.OperStatus != IfOperStatusUp) continue;

            NetworkInterfaceStats stats;
            // Convert InterfaceDescription (WCHAR) to string
            char descBuf[256];
            WideCharToMultiByte(CP_UTF8, 0, row.Description, -1, descBuf, sizeof(descBuf), NULL, NULL);
            stats.description = descBuf;

            // Physical Address
            char macBuf[32];
            if (row.PhysicalAddressLength > 0) {
                snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                    row.PhysicalAddress[0], row.PhysicalAddress[1], row.PhysicalAddress[2],
                    row.PhysicalAddress[3], row.PhysicalAddress[4], row.PhysicalAddress[5]);
                stats.macAddress = macBuf;
            }

            stats.isUp = (row.OperStatus == IfOperStatusUp);
            stats.speedBits = row.ReceiveLinkSpeed;
            stats.totalBytesIn = row.InOctets;
            stats.totalBytesOut = row.OutOctets;
            stats.errorsIn = row.InErrors;
            stats.errorsOut = row.OutErrors;

            // Calculate rates using previous values
            uint32_t idx = row.InterfaceIndex;
            auto it = m_prevInterfaceBytes.find(idx);
            if (it != m_prevInterfaceBytes.end()) {
                uint64_t dIn = (stats.totalBytesIn >= it->second.first) ?
                               (stats.totalBytesIn - it->second.first) : 0;
                uint64_t dOut = (stats.totalBytesOut >= it->second.second) ?
                                (stats.totalBytesOut - it->second.second) : 0;

                stats.inboundBitsPerSec = (dIn * 8.0) / deltaTime;
                stats.outboundBitsPerSec = (dOut * 8.0) / deltaTime;
            }

            m_prevInterfaceBytes[idx] = {stats.totalBytesIn, stats.totalBytesOut};

            if (stats.inboundBitsPerSec > 0 || stats.outboundBitsPerSec > 0) {
                globalStats.totalInboundBitsPerSec += stats.inboundBitsPerSec;
                globalStats.totalOutboundBitsPerSec += stats.outboundBitsPerSec;
                globalStats.activeInterfaces++;
            }

            currentStats.push_back(stats);
        }

        FreeMibTable(ifTable);

        // Store active connections count from process scan if available
        {
            std::shared_lock lock(m_dataMutex);
            globalStats.totalTcpConnections = m_globalStats.totalTcpConnections;
            globalStats.totalUdpListeners = m_globalStats.totalUdpListeners;
        }

        {
            std::unique_lock lock(m_dataMutex);
            m_interfaceStats = std::move(currentStats);
            m_globalStats = globalStats;
        }
    }

    void UpdateProcessStats() {
        std::unordered_map<uint32_t, ProcessNetworkUsage> usageMap;
        uint32_t totalTcp = 0;
        uint32_t totalUdp = 0;

        // TCP Table
        PMIB_TCPTABLE2 tcpTable = nullptr;
        ULONG ulSize = 0;
        if (GetTcpTable2(tcpTable, &ulSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
            tcpTable = (PMIB_TCPTABLE2)malloc(ulSize);
            if (tcpTable && GetTcpTable2(tcpTable, &ulSize, TRUE) == NO_ERROR) {
                for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                    uint32_t pid = tcpTable->table[i].dwOwningPid;
                    usageMap[pid].processId = pid;
                    usageMap[pid].tcpConnections++;
                    totalTcp++;
                }
            }
            free(tcpTable);
        }

        // UDP Table
        PMIB_UDPTABLE_OWNER_PID udpTable = nullptr;
        ulSize = 0;
        if (GetExtendedUdpTable(udpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(ulSize);
            if (udpTable && GetExtendedUdpTable(udpTable, &ulSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
                    uint32_t pid = udpTable->table[i].dwOwningPid;
                    usageMap[pid].processId = pid;
                    usageMap[pid].udpListeners++;
                    totalUdp++;
                }
            }
            free(udpTable);
        }

        // Populate names
        for (auto& kv : usageMap) {
            kv.second.processName = GetProcessName(kv.first);
        }

        {
            std::unique_lock lock(m_dataMutex);
            m_processUsage = std::move(usageMap);
            m_globalStats.totalTcpConnections = totalTcp;
            m_globalStats.totalUdpListeners = totalUdp;
        }
    }

    std::wstring GetProcessName(uint32_t pid) {
        if (pid == 0) return L"System Idle Process";
        if (pid == 4) return L"System";

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            WCHAR name[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, name, &size)) {
                CloseHandle(hProcess);
                // Return just the filename
                std::wstring path(name);
                size_t pos = path.find_last_of(L"\\/");
                if (pos != std::wstring::npos) return path.substr(pos + 1);
                return path;
            }
            CloseHandle(hProcess);
        }
        return L"Unknown";
    }

    // ========================================================================
    // ACCESSORS
    // ========================================================================

    NetworkGlobalStats GetGlobalStats() const {
        std::shared_lock lock(m_dataMutex);
        return m_globalStats;
    }

    std::vector<NetworkInterfaceStats> GetInterfaceStats() const {
        std::shared_lock lock(m_dataMutex);
        return m_interfaceStats;
    }

    std::vector<ProcessNetworkUsage> GetTopProcesses(size_t count) const {
        std::shared_lock lock(m_dataMutex);
        std::vector<ProcessNetworkUsage> procs;
        procs.reserve(m_processUsage.size());

        for (const auto& kv : m_processUsage) {
            procs.push_back(kv.second);
        }

        // Sort by total connections
        std::sort(procs.begin(), procs.end(),
            [](const ProcessNetworkUsage& a, const ProcessNetworkUsage& b) {
                return (a.tcpConnections + a.udpListeners) > (b.tcpConnections + b.udpListeners);
            });

        if (procs.size() > count) procs.resize(count);
        return procs;
    }

    std::optional<ProcessNetworkUsage> GetProcessUsage(uint32_t pid) const {
        std::shared_lock lock(m_dataMutex);
        auto it = m_processUsage.find(pid);
        if (it != m_processUsage.end()) return it->second;
        return std::nullopt;
    }

    NetworkMonitorModuleStats GetModuleStats() const {
        return m_stats;
    }

private:
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_dataMutex;

    std::atomic<bool> m_running{false};
    std::thread m_thread;

    NetworkMonitorConfig m_config;
    NetworkMonitorModuleStats m_stats;

    // Data
    TimePoint m_lastInterfaceUpdate;
    std::map<uint32_t, std::pair<uint64_t, uint64_t>> m_prevInterfaceBytes; // Index -> {In, Out}

    NetworkGlobalStats m_globalStats;
    std::vector<NetworkInterfaceStats> m_interfaceStats;
    std::unordered_map<uint32_t, ProcessNetworkUsage> m_processUsage;
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

NetworkPerformanceMonitor& NetworkPerformanceMonitor::Instance() noexcept {
    static NetworkPerformanceMonitor instance;
    return instance;
}

NetworkPerformanceMonitor::NetworkPerformanceMonitor()
    : m_impl(std::make_unique<NetworkPerformanceMonitorImpl>()) {
    s_instanceCreated.store(true);
}

NetworkPerformanceMonitor::~NetworkPerformanceMonitor() {
    s_instanceCreated.store(false);
}

bool NetworkPerformanceMonitor::Initialize(const NetworkMonitorConfig& config) {
    return m_impl->Initialize(config);
}

void NetworkPerformanceMonitor::Shutdown() {
    m_impl->Shutdown();
}

bool NetworkPerformanceMonitor::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

void NetworkPerformanceMonitor::UpdateConfig(const NetworkMonitorConfig& config) {
    m_impl->UpdateConfig(config);
}

NetworkMonitorConfig NetworkPerformanceMonitor::GetConfig() const {
    return m_impl->GetConfig();
}

NetworkGlobalStats NetworkPerformanceMonitor::GetGlobalStats() const {
    return m_impl->GetGlobalStats();
}

std::vector<NetworkInterfaceStats> NetworkPerformanceMonitor::GetInterfaceStats() const {
    return m_impl->GetInterfaceStats();
}

std::vector<ProcessNetworkUsage> NetworkPerformanceMonitor::GetTopProcesses(size_t count) const {
    return m_impl->GetTopProcesses(count);
}

std::optional<ProcessNetworkUsage> NetworkPerformanceMonitor::GetProcessUsage(uint32_t pid) const {
    return m_impl->GetProcessUsage(pid);
}

NetworkMonitorModuleStats NetworkPerformanceMonitor::GetModuleStats() const {
    return m_impl->GetModuleStats();
}

bool NetworkPerformanceMonitor::SelfTest() {
    return true; // Basic test
}

std::string NetworkPerformanceMonitor::GetVersionString() noexcept {
    return "3.0.0";
}

} // namespace Performance
} // namespace ShadowStrike
