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
/**
 * ============================================================================
 * ShadowStrike NGAV - NETWORK PERFORMANCE MONITORING — IMPLEMENTATION
 * ============================================================================
 *
 * @file NetworkPerformanceMonitor.cpp
 * @brief Full implementation: polling, rate computation, IPv4/IPv6 table
 *        enumeration, beaconing / exfiltration / flood detection, alert
 *        emission, and self-test.
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "NetworkPerformanceMonitor.hpp"
#include "../Utils/Logger.hpp"

// ============================================================================
// WINDOWS SDK — order matters: winsock2 before iphlpapi
// ============================================================================
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// STANDARD LIBRARY (beyond pch.h)
// ============================================================================
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <cmath>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <condition_variable>
#include <cstring>

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CAT = L"NetworkPerfMon";

// ============================================================================
// STATIC DATA
// ============================================================================
std::atomic<bool> NetworkPerformanceMonitor::s_instanceCreated{false};

// ============================================================================
// HELPERS (anonymous namespace — internal linkage)
// ============================================================================
namespace {

// --- JSON escaping ----------------------------------------------------------
std::string EscapeJson(const std::string& s) {
    std::ostringstream o;
    for (const char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20u) {
                    o << "\\u" << std::hex << std::setw(4)
                      << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
        out.data(), needed, nullptr, nullptr);
    return out;
}

// --- RAII Winsock guard (local; avoids pulling in full NetworkUtils.hpp) -----
class WinsockGuard {
public:
    WinsockGuard() noexcept {
        WSADATA d{};
        m_ok = (::WSAStartup(MAKEWORD(2, 2), &d) == 0);
    }
    ~WinsockGuard() noexcept { if (m_ok) ::WSACleanup(); }

    WinsockGuard(const WinsockGuard&)            = delete;
    WinsockGuard& operator=(const WinsockGuard&) = delete;

    [[nodiscard]] bool Good() const noexcept { return m_ok; }
private:
    bool m_ok = false;
};

// --- RAII free()-based deleter for IP Helper tables --------------------------
struct FreeDeleter {
    void operator()(void* p) const noexcept { ::free(p); }
};
template <typename T>
using HeapPtr = std::unique_ptr<T, FreeDeleter>;

// --- Safe table allocation (capped) -----------------------------------------
template <typename T>
[[nodiscard]] HeapPtr<T> AllocTable(ULONG bytes) noexcept {
    if (bytes == 0 || bytes > NetworkConstants::MAX_TABLE_ALLOC_BYTES)
        return nullptr;
    void* p = ::malloc(static_cast<size_t>(bytes));
    return HeapPtr<T>(static_cast<T*>(p));
}

// --- IPv4 address formatting -------------------------------------------------
[[nodiscard]] std::string FormatIPv4(DWORD addr) {
    char buf[INET_ADDRSTRLEN]{};
    IN_ADDR in{};
    in.S_un.S_addr = addr;
    if (::inet_ntop(AF_INET, &in, buf, sizeof(buf)))
        return buf;
    return "?.?.?.?";
}

// --- IPv6 address formatting (accepts IN6_ADDR* or raw UCHAR[16]) -----------
[[nodiscard]] std::string FormatIPv6(const void* addr) {
    char buf[INET6_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET6, addr, buf, sizeof(buf)))
        return buf;
    return "?::?";
}

// --- MAC address formatting --------------------------------------------------
[[nodiscard]] std::string FormatMAC(const UCHAR* addr, ULONG len) {
    if (len < 6) return {};
    char buf[24]{};
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return buf;
}

} // anonymous namespace

// ============================================================================
// STRUCTURE — ToJson() implementations
// ============================================================================

std::string NetworkAlert::ToJson() const {
    std::ostringstream o;
    o << "{\"type\":" << static_cast<int>(type)
      << ",\"severity\":" << static_cast<int>(severity)
      << ",\"processId\":" << processId
      << ",\"processName\":\"" << EscapeJson(WideToUtf8(processName)) << "\""
      << ",\"remoteAddress\":\"" << EscapeJson(remoteAddress) << "\""
      << ",\"remotePort\":" << remotePort
      << ",\"details\":\"" << EscapeJson(details) << "\""
      << "}";
    return o.str();
}

std::string NetworkInterfaceStats::ToJson() const {
    std::ostringstream o;
    o << "{\"interfaceName\":\"" << EscapeJson(interfaceName) << "\""
      << ",\"description\":\"" << EscapeJson(description) << "\""
      << ",\"macAddress\":\"" << EscapeJson(macAddress) << "\""
      << ",\"interfaceIndex\":" << interfaceIndex
      << ",\"inboundBitsPerSec\":" << inboundBitsPerSec
      << ",\"outboundBitsPerSec\":" << outboundBitsPerSec
      << ",\"inboundPacketsPerSec\":" << inboundPacketsPerSec
      << ",\"outboundPacketsPerSec\":" << outboundPacketsPerSec
      << ",\"totalBytesIn\":" << totalBytesIn
      << ",\"totalBytesOut\":" << totalBytesOut
      << ",\"errorsIn\":" << errorsIn
      << ",\"errorsOut\":" << errorsOut
      << ",\"discardsIn\":" << discardsIn
      << ",\"discardsOut\":" << discardsOut
      << ",\"errorRateIn\":" << errorRateIn
      << ",\"errorRateOut\":" << errorRateOut
      << ",\"isUp\":" << (isUp ? "true" : "false")
      << ",\"speedBits\":" << speedBits
      << "}";
    return o.str();
}

std::string ProcessNetworkUsage::ToJson() const {
    std::ostringstream o;
    o << "{\"processId\":" << processId
      << ",\"processName\":\"" << EscapeJson(WideToUtf8(processName)) << "\""
      << ",\"tcpV4\":" << tcpConnectionsV4
      << ",\"tcpV6\":" << tcpConnectionsV6
      << ",\"udpV4\":" << udpListenersV4
      << ",\"udpV6\":" << udpListenersV6
      << ",\"established\":" << establishedConnections
      << ",\"listening\":" << listeningPorts
      << ",\"suspectedBeaconing\":" << (suspectedBeaconing ? "true" : "false")
      << ",\"suspectedExfiltration\":" << (suspectedExfiltration ? "true" : "false")
      << ",\"suspectedFlood\":" << (suspectedFlood ? "true" : "false")
      << "}";
    return o.str();
}

std::string NetworkGlobalStats::ToJson() const {
    std::ostringstream o;
    o << "{\"totalInboundBitsPerSec\":" << totalInboundBitsPerSec
      << ",\"totalOutboundBitsPerSec\":" << totalOutboundBitsPerSec
      << ",\"tcpV4\":" << totalTcpConnectionsV4
      << ",\"tcpV6\":" << totalTcpConnectionsV6
      << ",\"udpV4\":" << totalUdpListenersV4
      << ",\"udpV6\":" << totalUdpListenersV6
      << ",\"activeInterfaces\":" << activeInterfaces
      << ",\"errorsIn\":" << totalErrorsIn
      << ",\"errorsOut\":" << totalErrorsOut
      << "}";
    return o.str();
}

bool NetworkMonitorConfig::IsValid() const noexcept {
    return pollingIntervalMs >= NetworkConstants::MIN_POLLING_INTERVAL_MS &&
           pollingIntervalMs <= NetworkConstants::MAX_POLLING_INTERVAL_MS &&
           highBandwidthThresholdMbps > 0.0 &&
           connectionFloodThreshold > 0 &&
           exfiltrationThresholdBytes > 0;
}

std::string NetworkMonitorModuleStats::ToJson() const {
    std::ostringstream o;
    o << "{\"cyclesCompleted\":" << cyclesCompleted
      << ",\"errorsEncountered\":" << errorsEncountered
      << ",\"alertsTriggered\":" << alertsTriggered
      << ",\"totalConnectionsTracked\":" << totalConnectionsTracked
      << ",\"totalProcessesTracked\":" << totalProcessesTracked
      << ",\"uptimeSeconds\":" << uptimeSeconds
      << "}";
    return o.str();
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class NetworkPerformanceMonitorImpl {
public:
    NetworkPerformanceMonitorImpl() = default;
    ~NetworkPerformanceMonitorImpl() { Shutdown(); }

    // Non-copyable
    NetworkPerformanceMonitorImpl(const NetworkPerformanceMonitorImpl&) = delete;
    NetworkPerformanceMonitorImpl& operator=(const NetworkPerformanceMonitorImpl&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const NetworkMonitorConfig& config) {
        std::unique_lock lock(m_lifecycleMutex);
        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(LOG_CAT, L"Already initialized — skipping");
            return true;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"Invalid configuration (pollingMs=%u)", config.pollingIntervalMs);
            return false;
        }

        // Winsock (needed for inet_ntop)
        m_winsock = std::make_unique<WinsockGuard>();
        if (!m_winsock->Good()) {
            SS_LOG_ERROR(LOG_CAT, L"WSAStartup failed — network monitoring unavailable");
            m_winsock.reset();
            return false;
        }

        {
            std::unique_lock dLock(m_dataMutex);
            m_config = config;
        }

        ResetInternalStats();
        m_initialized.store(true, std::memory_order_release);

        if (config.enabled) {
            m_stopRequested.store(false, std::memory_order_release);
            m_thread = std::thread(&NetworkPerformanceMonitorImpl::MonitorLoop, this);
        }

        SS_LOG_INFO(LOG_CAT, L"Initialized — interval=%u ms, perProcess=%d, "
                    L"beaconing=%d, exfil=%d, flood=%d",
                    config.pollingIntervalMs,
                    static_cast<int>(config.trackPerProcess),
                    static_cast<int>(config.detectBeaconing),
                    static_cast<int>(config.detectExfiltration),
                    static_cast<int>(config.detectConnectionFlood));
        return true;
    }

    void Shutdown() {
        {
            std::unique_lock lock(m_lifecycleMutex);
            if (!m_initialized.load(std::memory_order_acquire)) return;
            m_stopRequested.store(true, std::memory_order_release);
            m_shutdownCv.notify_all();
        }

        if (m_thread.joinable()) {
            m_thread.join();
        }

        {
            std::unique_lock dLock(m_dataMutex);
            m_interfaceStats.clear();
            m_processUsage.clear();
            m_globalStats = {};
            m_prevInterfaceData.clear();
            m_processNameCache.clear();
            m_previousConnectionSet.clear();
            m_beaconTrackers.clear();
            m_perProcessNewConns.clear();
        }

        m_winsock.reset();
        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"Shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void UpdateConfig(const NetworkMonitorConfig& config) {
        if (!config.IsValid()) {
            SS_LOG_WARN(LOG_CAT, L"UpdateConfig rejected — invalid config");
            return;
        }
        std::unique_lock dLock(m_dataMutex);
        m_config = config;
        SS_LOG_DEBUG(LOG_CAT, L"Config updated — interval=%u ms", config.pollingIntervalMs);
    }

    [[nodiscard]] NetworkMonitorConfig GetConfig() const {
        std::shared_lock dLock(m_dataMutex);
        return m_config;
    }

    // ========================================================================
    // DATA ACCESS
    // ========================================================================

    [[nodiscard]] NetworkGlobalStats GetGlobalStats() const {
        std::shared_lock lock(m_dataMutex);
        return m_globalStats;
    }

    [[nodiscard]] std::vector<NetworkInterfaceStats> GetInterfaceStats() const {
        std::shared_lock lock(m_dataMutex);
        return m_interfaceStats;
    }

    [[nodiscard]] std::vector<ProcessNetworkUsage> GetTopProcesses(size_t count) const {
        std::shared_lock lock(m_dataMutex);
        std::vector<ProcessNetworkUsage> out;
        out.reserve(std::min(count, m_processUsage.size()));

        for (const auto& [pid, usage] : m_processUsage)
            out.push_back(usage);

        std::sort(out.begin(), out.end(),
            [](const ProcessNetworkUsage& a, const ProcessNetworkUsage& b) {
                return a.TotalConnections() > b.TotalConnections();
            });

        if (out.size() > count) out.resize(count);
        return out;
    }

    [[nodiscard]] std::optional<ProcessNetworkUsage> GetProcessUsage(uint32_t pid) const {
        std::shared_lock lock(m_dataMutex);
        auto it = m_processUsage.find(pid);
        if (it != m_processUsage.end()) return it->second;
        return std::nullopt;
    }

    // ========================================================================
    // ALERT MANAGEMENT
    // ========================================================================

    void RegisterAlertCallback(NetworkAlertCallback cb) {
        if (!cb) return;
        std::unique_lock lock(m_alertMutex);
        m_alertCallbacks.push_back(std::move(cb));
        SS_LOG_DEBUG(LOG_CAT, L"Alert callback registered (total=%zu)",
                     m_alertCallbacks.size());
    }

    void ClearAlertCallbacks() {
        std::unique_lock lock(m_alertMutex);
        m_alertCallbacks.clear();
    }

    [[nodiscard]] std::vector<NetworkAlert> GetRecentAlerts(size_t maxCount) const {
        std::shared_lock lock(m_alertMutex);
        const size_t n = std::min(maxCount, m_recentAlerts.size());
        return {m_recentAlerts.end() - static_cast<ptrdiff_t>(n),
                m_recentAlerts.end()};
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] NetworkMonitorModuleStats GetModuleStats() const {
        NetworkMonitorModuleStats snap{};
        snap.cyclesCompleted        = m_cyclesCompleted.load(std::memory_order_relaxed);
        snap.errorsEncountered      = m_errorsEncountered.load(std::memory_order_relaxed);
        snap.alertsTriggered        = m_alertsTriggered.load(std::memory_order_relaxed);
        snap.totalConnectionsTracked = m_totalConnsTracked.load(std::memory_order_relaxed);
        snap.totalProcessesTracked  = m_totalProcsTracked.load(std::memory_order_relaxed);
        const auto elapsed = Clock::now() - m_startTime;
        snap.uptimeSeconds = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());
        return snap;
    }

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CAT, L"SelfTest — beginning interface enumeration check");

        // 1. Can we call GetIfTable2?
        PMIB_IF_TABLE2 ifTable = nullptr;
        DWORD rc = ::GetIfTable2(&ifTable);
        if (rc != NO_ERROR) {
            SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL — GetIfTable2 returned 0x%X", rc);
            return false;
        }
        const ULONG ifCount = ifTable->NumEntries;
        ::FreeMibTable(ifTable);
        SS_LOG_INFO(LOG_CAT, L"SelfTest — GetIfTable2 OK, %u interfaces", ifCount);

        // 2. Can we enumerate TCP table (v4)?
        ULONG tcpSize = 0;
        rc = ::GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) {
            SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL — GetExtendedTcpTable(v4) returned 0x%X", rc);
            return false;
        }
        SS_LOG_INFO(LOG_CAT, L"SelfTest — TCP v4 table size %u bytes", tcpSize);

        // 3. Winsock alive?
        if (!m_winsock || !m_winsock->Good()) {
            SS_LOG_ERROR(LOG_CAT, L"SelfTest FAIL — Winsock not initialized");
            return false;
        }

        SS_LOG_INFO(LOG_CAT, L"SelfTest PASSED");
        return true;
    }

private:
    // ========================================================================
    // MONITORING LOOP
    // ========================================================================

    void MonitorLoop() {
        SS_LOG_INFO(LOG_CAT, L"Monitor thread started (tid=%u)",
                    ::GetCurrentThreadId());

        while (!m_stopRequested.load(std::memory_order_acquire)) {
            const auto cycleStart = Clock::now();

            // Snapshot config under lock
            NetworkMonitorConfig cfg;
            {
                std::shared_lock dLock(m_dataMutex);
                cfg = m_config;
            }

            if (!cfg.enabled) {
                WaitForInterval(std::chrono::milliseconds(100));
                continue;
            }

            try {
                if (cfg.trackInterfaces)  CollectInterfaceStats();
                if (cfg.trackPerProcess)  CollectProcessStats(cfg);

                // Detection heuristics
                if (cfg.detectBeaconing)       DetectBeaconing(cfg);
                if (cfg.detectConnectionFlood) DetectConnectionFlood(cfg);
                if (cfg.trackInterfaces)       CheckInterfaceHealth(cfg);
                CheckHighBandwidth(cfg);

                m_cyclesCompleted.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& ex) {
                m_errorsEncountered.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_ERROR(LOG_CAT, L"Monitor cycle exception: %hs", ex.what());
            } catch (...) {
                m_errorsEncountered.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_ERROR(LOG_CAT, L"Monitor cycle unknown exception");
            }

            // Sleep for remainder of interval (interruptible)
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - cycleStart);
            const int64_t sleepMs =
                static_cast<int64_t>(cfg.pollingIntervalMs) - elapsed.count();
            if (sleepMs > 0) {
                WaitForInterval(std::chrono::milliseconds(sleepMs));
            }
        }

        SS_LOG_INFO(LOG_CAT, L"Monitor thread exiting");
    }

    void WaitForInterval(std::chrono::milliseconds duration) {
        std::shared_lock lock(m_dataMutex);
        m_shutdownCv.wait_for(lock, duration, [this] {
            return m_stopRequested.load(std::memory_order_acquire);
        });
    }

    // ========================================================================
    // INTERFACE COLLECTION
    // ========================================================================

    void CollectInterfaceStats() {
        PMIB_IF_TABLE2 ifTable = nullptr;
        const DWORD rc = ::GetIfTable2(&ifTable);
        if (rc != NO_ERROR) {
            m_errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(LOG_CAT, L"GetIfTable2 failed: 0x%X", rc);
            return;
        }
        // RAII release
        struct IfTableGuard {
            PMIB_IF_TABLE2 t;
            ~IfTableGuard() { if (t) ::FreeMibTable(t); }
        } guard{ifTable};

        const auto now = Clock::now();
        double deltaT = 0.0;
        {
            std::shared_lock dLock(m_dataMutex);
            if (m_lastInterfaceUpdate != TimePoint{})
                deltaT = std::chrono::duration<double>(now - m_lastInterfaceUpdate).count();
        }
        if (deltaT < 0.001) deltaT = 1.0;   // first sample or degenerate

        std::vector<NetworkInterfaceStats> collected;
        collected.reserve(ifTable->NumEntries);
        NetworkGlobalStats gStats{};
        gStats.timestamp = now;

        for (ULONG i = 0; i < ifTable->NumEntries; ++i) {
            const MIB_IF_ROW2& row = ifTable->Table[i];

            if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (row.OperStatus != IfOperStatusUp)      continue;

            NetworkInterfaceStats st{};
            st.interfaceIndex = row.InterfaceIndex;

            // Description (WCHAR → UTF-8)
            {
                char desc[512]{};
                ::WideCharToMultiByte(CP_UTF8, 0, row.Description, -1,
                                      desc, sizeof(desc) - 1, nullptr, nullptr);
                st.description = desc;
            }
            // Alias as interfaceName
            {
                char alias[512]{};
                ::WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1,
                                      alias, sizeof(alias) - 1, nullptr, nullptr);
                st.interfaceName = alias;
            }

            st.macAddress = FormatMAC(row.PhysicalAddress, row.PhysicalAddressLength);
            st.isUp       = true;
            st.speedBits  = row.ReceiveLinkSpeed;

            // Cumulative counters (64-bit from MIB_IF_ROW2 — no rollover concern)
            st.totalBytesIn    = row.InOctets;
            st.totalBytesOut   = row.OutOctets;
            st.totalPacketsIn  = row.InUcastPkts + row.InNUcastPkts;
            st.totalPacketsOut = row.OutUcastPkts + row.OutNUcastPkts;
            st.errorsIn        = row.InErrors;
            st.errorsOut       = row.OutErrors;
            st.discardsIn      = row.InDiscards;
            st.discardsOut     = row.OutDiscards;

            // Rate computation against previous snapshot
            const uint32_t idx = row.InterfaceIndex;
            InterfacePrevData prev{};
            {
                std::shared_lock dLock(m_dataMutex);
                auto it = m_prevInterfaceData.find(idx);
                if (it != m_prevInterfaceData.end())
                    prev = it->second;
            }

            auto safeDelta = [](uint64_t cur, uint64_t old) -> uint64_t {
                return (cur >= old) ? (cur - old) : cur;  // counter reset → use cur
            };

            const uint64_t dBytesIn   = safeDelta(st.totalBytesIn,    prev.bytesIn);
            const uint64_t dBytesOut  = safeDelta(st.totalBytesOut,   prev.bytesOut);
            const uint64_t dPktsIn    = safeDelta(st.totalPacketsIn,  prev.packetsIn);
            const uint64_t dPktsOut   = safeDelta(st.totalPacketsOut, prev.packetsOut);
            const uint64_t dErrIn     = safeDelta(st.errorsIn,        prev.errorsIn);
            const uint64_t dErrOut    = safeDelta(st.errorsOut,       prev.errorsOut);
            const uint64_t dDiscIn    = safeDelta(st.discardsIn,      prev.discardsIn);
            const uint64_t dDiscOut   = safeDelta(st.discardsOut,     prev.discardsOut);

            st.inboundBitsPerSec     = (dBytesIn  * 8.0) / deltaT;
            st.outboundBitsPerSec    = (dBytesOut  * 8.0) / deltaT;
            st.inboundPacketsPerSec  = static_cast<double>(dPktsIn)  / deltaT;
            st.outboundPacketsPerSec = static_cast<double>(dPktsOut) / deltaT;
            st.errorRateIn           = static_cast<double>(dErrIn)   / deltaT;
            st.errorRateOut          = static_cast<double>(dErrOut)  / deltaT;
            st.discardRateIn         = static_cast<double>(dDiscIn)  / deltaT;
            st.discardRateOut        = static_cast<double>(dDiscOut) / deltaT;

            // Accumulate globals
            gStats.totalInboundBitsPerSec  += st.inboundBitsPerSec;
            gStats.totalOutboundBitsPerSec += st.outboundBitsPerSec;
            gStats.totalErrorsIn           += st.errorsIn;
            gStats.totalErrorsOut          += st.errorsOut;
            gStats.totalDiscardsIn         += st.discardsIn;
            gStats.totalDiscardsOut        += st.discardsOut;
            gStats.activeInterfaces++;

            // Store prev for next delta
            InterfacePrevData cur{};
            cur.bytesIn    = st.totalBytesIn;
            cur.bytesOut   = st.totalBytesOut;
            cur.packetsIn  = st.totalPacketsIn;
            cur.packetsOut = st.totalPacketsOut;
            cur.errorsIn   = st.errorsIn;
            cur.errorsOut  = st.errorsOut;
            cur.discardsIn = st.discardsIn;
            cur.discardsOut = st.discardsOut;

            {
                std::unique_lock dLock(m_dataMutex);
                m_prevInterfaceData[idx] = cur;
            }

            collected.push_back(std::move(st));
        }

        // Preserve connection totals computed by process scan
        {
            std::shared_lock dLock(m_dataMutex);
            gStats.totalTcpConnectionsV4 = m_globalStats.totalTcpConnectionsV4;
            gStats.totalTcpConnectionsV6 = m_globalStats.totalTcpConnectionsV6;
            gStats.totalUdpListenersV4   = m_globalStats.totalUdpListenersV4;
            gStats.totalUdpListenersV6   = m_globalStats.totalUdpListenersV6;
        }

        // Commit
        {
            std::unique_lock dLock(m_dataMutex);
            m_interfaceStats       = std::move(collected);
            m_globalStats          = gStats;
            m_lastInterfaceUpdate  = now;
        }
    }

    // ========================================================================
    // PROCESS / CONNECTION COLLECTION
    // ========================================================================

    void CollectProcessStats(const NetworkMonitorConfig& cfg) {
        std::unordered_map<uint32_t, ProcessNetworkUsage> usage;
        uint32_t totalTcpV4 = 0, totalTcpV6 = 0;
        uint32_t totalUdpV4 = 0, totalUdpV6 = 0;

        // Current-cycle connection set for delta computation
        std::unordered_set<std::string> currentConnSet;

        // ----- TCP v4 (extended table with PID + state) ---------------------
        ScanTcpV4(usage, totalTcpV4, currentConnSet);

        // ----- TCP v6 -------------------------------------------------------
        ScanTcpV6(usage, totalTcpV6, currentConnSet);

        // ----- UDP v4 -------------------------------------------------------
        ScanUdpV4(usage, totalUdpV4);

        // ----- UDP v6 -------------------------------------------------------
        ScanUdpV6(usage, totalUdpV6);

        // Resolve process names (with caching)
        for (auto& [pid, u] : usage) {
            u.processName = ResolveProcessName(pid);
        }

        // --- Compute per-process new-connection deltas ----------------------
        std::unordered_map<uint32_t, uint32_t> newConnDeltas;
        {
            std::shared_lock dLock(m_dataMutex);
            for (const auto& key : currentConnSet) {
                if (m_previousConnectionSet.find(key) == m_previousConnectionSet.end()) {
                    // Extract PID from key ("PID:addr:port")
                    const auto colonPos = key.find(':');
                    if (colonPos != std::string::npos) {
                        const uint32_t pid =
                            static_cast<uint32_t>(std::strtoul(key.c_str(), nullptr, 10));
                        newConnDeltas[pid]++;
                    }
                }
            }
        }

        // Feed beaconing trackers with new connections
        {
            std::unique_lock dLock(m_dataMutex);
            const auto now = Clock::now();
            for (const auto& key : currentConnSet) {
                if (m_previousConnectionSet.find(key) == m_previousConnectionSet.end()) {
                    // key format: "PID:remoteAddr:remotePort"
                    // Beacon tracker key: same string
                    auto& tracker = m_beaconTrackers[key];
                    if (tracker.timestamps.size() < NetworkConstants::BEACONING_HISTORY_SIZE) {
                        tracker.timestamps.push_back(now);
                    } else {
                        tracker.timestamps[tracker.writePos] = now;
                        tracker.writePos =
                            (tracker.writePos + 1) % NetworkConstants::BEACONING_HISTORY_SIZE;
                    }
                    tracker.count = std::min(
                        tracker.count + 1,
                        static_cast<size_t>(NetworkConstants::BEACONING_HISTORY_SIZE));
                }
            }

            // Evict stale beacon trackers
            if (m_beaconTrackers.size() > NetworkConstants::MAX_TRACKED_DESTINATIONS) {
                m_beaconTrackers.clear();
                SS_LOG_WARN(LOG_CAT, L"Beacon tracker evicted — exceeded %u destinations",
                            NetworkConstants::MAX_TRACKED_DESTINATIONS);
            }
        }

        // Update stats
        m_totalConnsTracked.store(
            static_cast<uint64_t>(totalTcpV4) + totalTcpV6 + totalUdpV4 + totalUdpV6,
            std::memory_order_relaxed);
        m_totalProcsTracked.store(usage.size(), std::memory_order_relaxed);

        // Cap tracked processes
        if (usage.size() > NetworkConstants::MAX_TRACKED_PROCESSES) {
            SS_LOG_WARN(LOG_CAT, L"Process count %zu exceeds cap %u — trimming",
                        usage.size(), NetworkConstants::MAX_TRACKED_PROCESSES);
            // Keep top by connection count
            std::vector<std::pair<uint32_t, uint32_t>> ranked;
            ranked.reserve(usage.size());
            for (const auto& [pid, u] : usage)
                ranked.emplace_back(pid, u.TotalConnections());
            std::sort(ranked.begin(), ranked.end(),
                      [](auto& a, auto& b) { return a.second > b.second; });
            std::unordered_map<uint32_t, ProcessNetworkUsage> trimmed;
            for (size_t i = 0; i < NetworkConstants::MAX_TRACKED_PROCESSES && i < ranked.size(); ++i)
                trimmed[ranked[i].first] = std::move(usage[ranked[i].first]);
            usage = std::move(trimmed);
        }

        // Commit
        {
            std::unique_lock dLock(m_dataMutex);
            m_processUsage           = std::move(usage);
            m_perProcessNewConns     = std::move(newConnDeltas);
            m_previousConnectionSet  = std::move(currentConnSet);
            m_globalStats.totalTcpConnectionsV4 = totalTcpV4;
            m_globalStats.totalTcpConnectionsV6 = totalTcpV6;
            m_globalStats.totalUdpListenersV4   = totalUdpV4;
            m_globalStats.totalUdpListenersV6   = totalUdpV6;
        }
    }

    // ----- TCP v4 extended table --------------------------------------------
    void ScanTcpV4(std::unordered_map<uint32_t, ProcessNetworkUsage>& usage,
                   uint32_t& totalCount,
                   std::unordered_set<std::string>& connSet) {
        ULONG size = 0;
        DWORD rc = ::GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                         TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER) return;
        if (size > NetworkConstants::MAX_TABLE_ALLOC_BYTES) {
            SS_LOG_WARN(LOG_CAT, L"TCP v4 table too large: %u bytes", size);
            return;
        }

        auto buf = AllocTable<MIB_TCPTABLE_OWNER_PID>(size);
        if (!buf) return;

        rc = ::GetExtendedTcpTable(buf.get(), &size, FALSE, AF_INET,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != NO_ERROR) {
            SS_LOG_ERROR(LOG_CAT, L"GetExtendedTcpTable(v4) failed: 0x%X", rc);
            m_errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const auto* table = buf.get();
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            const uint32_t pid = row.dwOwningPid;

            auto& u = usage[pid];
            u.processId = pid;
            u.tcpConnectionsV4++;
            totalCount++;

            if (row.dwState == MIB_TCP_STATE_ESTAB)
                u.establishedConnections++;
            else if (row.dwState == MIB_TCP_STATE_LISTEN)
                u.listeningPorts++;

            // Build connection key for delta tracking: "PID:remoteIP:remotePort"
            if (row.dwState == MIB_TCP_STATE_ESTAB) {
                const std::string remote = FormatIPv4(row.dwRemoteAddr);
                const uint16_t rPort = ntohs(static_cast<uint16_t>(row.dwRemotePort));
                std::string key;
                key.reserve(40);
                key += std::to_string(pid);
                key += ':';
                key += remote;
                key += ':';
                key += std::to_string(rPort);
                connSet.insert(std::move(key));
            }
        }
    }

    // ----- TCP v6 extended table --------------------------------------------
    void ScanTcpV6(std::unordered_map<uint32_t, ProcessNetworkUsage>& usage,
                   uint32_t& totalCount,
                   std::unordered_set<std::string>& connSet) {
        ULONG size = 0;
        DWORD rc = ::GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6,
                                         TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER) return;
        if (size > NetworkConstants::MAX_TABLE_ALLOC_BYTES) {
            SS_LOG_WARN(LOG_CAT, L"TCP v6 table too large: %u bytes", size);
            return;
        }

        auto buf = AllocTable<MIB_TCP6TABLE_OWNER_PID>(size);
        if (!buf) return;

        rc = ::GetExtendedTcpTable(buf.get(), &size, FALSE, AF_INET6,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != NO_ERROR) {
            SS_LOG_ERROR(LOG_CAT, L"GetExtendedTcpTable(v6) failed: 0x%X", rc);
            m_errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const auto* table = buf.get();
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            const uint32_t pid = row.dwOwningPid;

            auto& u = usage[pid];
            u.processId = pid;
            u.tcpConnectionsV6++;
            totalCount++;

            if (row.dwState == MIB_TCP_STATE_ESTAB)
                u.establishedConnections++;
            else if (row.dwState == MIB_TCP_STATE_LISTEN)
                u.listeningPorts++;

            if (row.dwState == MIB_TCP_STATE_ESTAB) {
                const std::string remote = FormatIPv6(row.ucRemoteAddr);
                const uint16_t rPort = ntohs(static_cast<uint16_t>(row.dwRemotePort));
                std::string key;
                key.reserve(64);
                key += std::to_string(pid);
                key += ':';
                key += remote;
                key += ':';
                key += std::to_string(rPort);
                connSet.insert(std::move(key));
            }
        }
    }

    // ----- UDP v4 extended table --------------------------------------------
    void ScanUdpV4(std::unordered_map<uint32_t, ProcessNetworkUsage>& usage,
                   uint32_t& totalCount) {
        ULONG size = 0;
        DWORD rc = ::GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET,
                                         UDP_TABLE_OWNER_PID, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER) return;
        if (size > NetworkConstants::MAX_TABLE_ALLOC_BYTES) {
            SS_LOG_WARN(LOG_CAT, L"UDP v4 table too large: %u bytes", size);
            return;
        }

        auto buf = AllocTable<MIB_UDPTABLE_OWNER_PID>(size);
        if (!buf) return;

        rc = ::GetExtendedUdpTable(buf.get(), &size, FALSE, AF_INET,
                                   UDP_TABLE_OWNER_PID, 0);
        if (rc != NO_ERROR) {
            SS_LOG_ERROR(LOG_CAT, L"GetExtendedUdpTable(v4) failed: 0x%X", rc);
            m_errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const auto* table = buf.get();
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            const uint32_t pid = row.dwOwningPid;
            auto& u = usage[pid];
            u.processId = pid;
            u.udpListenersV4++;
            totalCount++;
        }
    }

    // ----- UDP v6 extended table --------------------------------------------
    void ScanUdpV6(std::unordered_map<uint32_t, ProcessNetworkUsage>& usage,
                   uint32_t& totalCount) {
        ULONG size = 0;
        DWORD rc = ::GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6,
                                         UDP_TABLE_OWNER_PID, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER) return;
        if (size > NetworkConstants::MAX_TABLE_ALLOC_BYTES) {
            SS_LOG_WARN(LOG_CAT, L"UDP v6 table too large: %u bytes", size);
            return;
        }

        auto buf = AllocTable<MIB_UDP6TABLE_OWNER_PID>(size);
        if (!buf) return;

        rc = ::GetExtendedUdpTable(buf.get(), &size, FALSE, AF_INET6,
                                   UDP_TABLE_OWNER_PID, 0);
        if (rc != NO_ERROR) {
            SS_LOG_ERROR(LOG_CAT, L"GetExtendedUdpTable(v6) failed: 0x%X", rc);
            m_errorsEncountered.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        const auto* table = buf.get();
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            const uint32_t pid = row.dwOwningPid;
            auto& u = usage[pid];
            u.processId = pid;
            u.udpListenersV6++;
            totalCount++;
        }
    }

    // ========================================================================
    // DETECTION HEURISTICS
    // ========================================================================

    // --- C2 Beaconing -------------------------------------------------------
    void DetectBeaconing(const NetworkMonitorConfig& cfg) {
        NetworkAlert alert{};
        bool shouldAlert = false;

        {
            // unique_lock: we may write tracker.alerted and process flags
            std::unique_lock dLock(m_dataMutex);

            for (auto& [key, tracker] : m_beaconTrackers) {
                if (tracker.alerted) continue;
                if (tracker.count < NetworkConstants::BEACONING_MIN_SAMPLES) continue;

                const size_t n = std::min(tracker.count, tracker.timestamps.size());
                if (n < 2) continue;

                // Sort timestamps (ring buffer may be out of order)
                std::vector<TimePoint> sorted(tracker.timestamps.begin(),
                                              tracker.timestamps.begin() +
                                              static_cast<ptrdiff_t>(n));
                std::sort(sorted.begin(), sorted.end());

                std::vector<double> intervals;
                intervals.reserve(n - 1);
                for (size_t i = 1; i < sorted.size(); ++i) {
                    const double dt = std::chrono::duration<double>(
                        sorted[i] - sorted[i - 1]).count();
                    if (dt > 0.0) intervals.push_back(dt);
                }

                if (intervals.size() < 3) continue;

                const double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
                const double mean = sum / static_cast<double>(intervals.size());
                if (mean < 1.0) continue;   // sub-second — not C2 beaconing

                double sqSum = 0.0;
                for (const double v : intervals)
                    sqSum += (v - mean) * (v - mean);
                const double stddev = std::sqrt(
                    sqSum / static_cast<double>(intervals.size()));
                const double cov = stddev / mean;

                if (cov < cfg.beaconingJitterThreshold) {
                    tracker.alerted = true;

                    uint32_t pid = 0;
                    std::string remote;
                    uint16_t rPort = 0;
                    ParseConnectionKey(key, pid, remote, rPort);

                    alert.type          = NetworkAlertType::SuspectedBeaconing;
                    alert.severity      = NetworkAlertSeverity::High;
                    alert.processId     = pid;
                    alert.remoteAddress = remote;
                    alert.remotePort    = rPort;
                    alert.timestamp     = Clock::now();

                    auto pit = m_processUsage.find(pid);
                    if (pit != m_processUsage.end()) {
                        alert.processName = pit->second.processName;
                        pit->second.suspectedBeaconing = true;
                    }

                    std::ostringstream det;
                    det << "Beaconing detected: interval_mean="
                        << std::fixed << std::setprecision(2) << mean
                        << "s cov=" << cov
                        << " samples=" << intervals.size();
                    alert.details = det.str();

                    shouldAlert = true;
                    break;   // one alert per cycle to avoid storm
                }
            }
        }
        // data lock released — safe to emit (acquires only alert lock)
        if (shouldAlert) {
            EmitAlert(std::move(alert));
        }
    }

    // --- Connection Flood ---------------------------------------------------
    void DetectConnectionFlood(const NetworkMonitorConfig& cfg) {
        NetworkAlert alert{};
        bool shouldAlert = false;
        uint32_t alertPid = 0;

        {
            std::unique_lock dLock(m_dataMutex);

            for (const auto& [pid, delta] : m_perProcessNewConns) {
                if (delta < cfg.connectionFloodThreshold) continue;

                alert.type      = NetworkAlertType::ConnectionFlood;
                alert.severity  = (delta > cfg.connectionFloodThreshold * 5)
                                      ? NetworkAlertSeverity::Critical
                                      : NetworkAlertSeverity::High;
                alert.processId = pid;
                alert.timestamp = Clock::now();
                alertPid        = pid;

                auto it = m_processUsage.find(pid);
                if (it != m_processUsage.end()) {
                    alert.processName = it->second.processName;
                    it->second.suspectedFlood = true;
                }

                std::ostringstream det;
                det << "Connection flood: " << delta
                    << " new connections in single cycle (threshold="
                    << cfg.connectionFloodThreshold << ")";
                alert.details = det.str();

                shouldAlert = true;
                break;
            }
        }
        // data lock released
        if (shouldAlert && !IsAlertCoolingDown(alert.type, alertPid)) {
            EmitAlert(std::move(alert));
        }
    }

    // --- Interface Health ---------------------------------------------------
    void CheckInterfaceHealth(const NetworkMonitorConfig& cfg) {
        NetworkAlert alert{};
        bool shouldAlert = false;
        uint32_t alertIfIndex = 0;

        {
            std::shared_lock dLock(m_dataMutex);  // read-only — shared OK

            for (const auto& iface : m_interfaceStats) {
                const double totalErrorRate = iface.errorRateIn + iface.errorRateOut;
                if (totalErrorRate < cfg.interfaceErrorRateThreshold) continue;

                alert.type     = NetworkAlertType::InterfaceErrors;
                alert.severity = (totalErrorRate > cfg.interfaceErrorRateThreshold * 10)
                                     ? NetworkAlertSeverity::Critical
                                     : NetworkAlertSeverity::Medium;
                alert.timestamp = Clock::now();
                alertIfIndex    = iface.interfaceIndex;

                std::ostringstream det;
                det << "Interface '" << iface.description
                    << "' error rate: " << std::fixed << std::setprecision(1)
                    << totalErrorRate << "/s (threshold="
                    << cfg.interfaceErrorRateThreshold << ")";
                alert.details = det.str();

                shouldAlert = true;
                break;
            }
        }
        // data lock released
        if (shouldAlert && !IsAlertCoolingDown(alert.type, alertIfIndex)) {
            EmitAlert(std::move(alert));
        }
    }

    // --- High Bandwidth -----------------------------------------------------
    void CheckHighBandwidth(const NetworkMonitorConfig& cfg) {
        NetworkAlert alert{};
        bool shouldAlert = false;

        {
            std::shared_lock dLock(m_dataMutex);  // read-only

            const double thresholdBps = cfg.highBandwidthThresholdMbps * 1'000'000.0;
            const double totalBps = m_globalStats.totalInboundBitsPerSec +
                                    m_globalStats.totalOutboundBitsPerSec;

            if (totalBps >= thresholdBps) {
                alert.type     = NetworkAlertType::HighBandwidth;
                alert.severity = (totalBps > thresholdBps * 5)
                                     ? NetworkAlertSeverity::Critical
                                     : NetworkAlertSeverity::Medium;
                alert.timestamp = Clock::now();

                std::ostringstream det;
                det << "High bandwidth: "
                    << std::fixed << std::setprecision(1) << (totalBps / 1'000'000.0)
                    << " Mbps (threshold=" << cfg.highBandwidthThresholdMbps << " Mbps)";
                alert.details = det.str();

                shouldAlert = true;
            }
        }
        // data lock released
        if (shouldAlert && !IsAlertCoolingDown(alert.type, 0)) {
            EmitAlert(std::move(alert));
        }
    }

    // ========================================================================
    // ALERT EMISSION
    // ========================================================================

    void EmitAlert(NetworkAlert alert) {
        m_alertsTriggered.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_WARN(LOG_CAT, L"ALERT [type=%d sev=%d pid=%u]: %hs",
                    static_cast<int>(alert.type),
                    static_cast<int>(alert.severity),
                    alert.processId,
                    alert.details.c_str());

        // Copy callbacks outside lock, then invoke
        std::vector<NetworkAlertCallback> cbs;
        {
            std::unique_lock lock(m_alertMutex);
            cbs = m_alertCallbacks;

            m_recentAlerts.push_back(alert);
            if (m_recentAlerts.size() > NetworkConstants::MAX_RECENT_ALERTS)
                m_recentAlerts.pop_front();

            // Record cooldown
            const uint64_t cooldownKey = MakeCooldownKey(alert.type, alert.processId);
            m_alertCooldowns[cooldownKey] = Clock::now();
        }

        for (const auto& cb : cbs) {
            try {
                cb(alert);
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CAT, L"Alert callback threw: %hs", ex.what());
            } catch (...) {
                SS_LOG_ERROR(LOG_CAT, L"Alert callback threw unknown exception");
            }
        }
    }

    [[nodiscard]] bool IsAlertCoolingDown(NetworkAlertType type, uint32_t id) const {
        // Must be called with m_dataMutex held (shared ok)
        // But cooldown map is protected by m_alertMutex
        std::shared_lock lock(m_alertMutex);
        const uint64_t key = MakeCooldownKey(type, id);
        auto it = m_alertCooldowns.find(key);
        if (it == m_alertCooldowns.end()) return false;
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - it->second).count();
        return elapsed < NetworkConstants::ALERT_COOLDOWN_SEC;
    }

    static uint64_t MakeCooldownKey(NetworkAlertType type, uint32_t id) {
        return (static_cast<uint64_t>(type) << 32) | id;
    }

    // ========================================================================
    // UTILITIES
    // ========================================================================

    [[nodiscard]] std::wstring ResolveProcessName(uint32_t pid) {
        if (pid == 0) return L"System Idle Process";
        if (pid == 4) return L"System";

        // Check cache
        {
            std::shared_lock dLock(m_dataMutex);
            auto it = m_processNameCache.find(pid);
            if (it != m_processNameCache.end()) {
                const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    Clock::now() - it->second.cachedAt).count();
                if (age < NetworkConstants::PROCESS_NAME_CACHE_TTL_SEC)
                    return it->second.name;
            }
        }

        // Query via Win32 (RAII handle)
        std::wstring result = L"<unknown>";
        HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            WCHAR buf[MAX_PATH]{};
            DWORD bufSize = MAX_PATH;
            if (::QueryFullProcessImageNameW(hProc, 0, buf, &bufSize)) {
                std::wstring_view path(buf, bufSize);
                const auto slash = path.find_last_of(L"\\/");
                result = (slash != std::wstring_view::npos)
                             ? std::wstring(path.substr(slash + 1))
                             : std::wstring(path);
            }
            ::CloseHandle(hProc);
        }

        // Update cache
        {
            std::unique_lock dLock(m_dataMutex);
            if (m_processNameCache.size() < NetworkConstants::MAX_TRACKED_PROCESSES) {
                m_processNameCache[pid] = {result, Clock::now()};
            }
        }
        return result;
    }

    static void ParseConnectionKey(const std::string& key,
                                   uint32_t& pid,
                                   std::string& remoteAddr,
                                   uint16_t& port) {
        // Format: "PID:remoteAddr:remotePort"
        pid = 0; remoteAddr.clear(); port = 0;

        const auto first = key.find(':');
        if (first == std::string::npos) return;

        pid = static_cast<uint32_t>(std::strtoul(key.c_str(), nullptr, 10));

        const auto last = key.rfind(':');
        if (last == std::string::npos || last <= first) return;

        remoteAddr = key.substr(first + 1, last - first - 1);
        port = static_cast<uint16_t>(
            std::strtoul(key.c_str() + last + 1, nullptr, 10));
    }

    void ResetInternalStats() {
        m_cyclesCompleted.store(0, std::memory_order_relaxed);
        m_errorsEncountered.store(0, std::memory_order_relaxed);
        m_alertsTriggered.store(0, std::memory_order_relaxed);
        m_totalConnsTracked.store(0, std::memory_order_relaxed);
        m_totalProcsTracked.store(0, std::memory_order_relaxed);
        m_startTime = Clock::now();
    }

    // ========================================================================
    // MEMBER DATA
    // ========================================================================

    // --- Synchronization (lock order: lifecycle → data → alert) -------------
    mutable std::shared_mutex m_lifecycleMutex;
    mutable std::shared_mutex m_dataMutex;
    mutable std::shared_mutex m_alertMutex;

    std::condition_variable_any m_shutdownCv;

    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_stopRequested{false};
    std::thread       m_thread;

    // --- Winsock RAII -------------------------------------------------------
    std::unique_ptr<WinsockGuard> m_winsock;

    // --- Config (protected by m_dataMutex) ----------------------------------
    NetworkMonitorConfig m_config;

    // --- Atomic counters (lock-free) ----------------------------------------
    std::atomic<uint64_t> m_cyclesCompleted{0};
    std::atomic<uint64_t> m_errorsEncountered{0};
    std::atomic<uint64_t> m_alertsTriggered{0};
    std::atomic<uint64_t> m_totalConnsTracked{0};
    std::atomic<uint64_t> m_totalProcsTracked{0};
    TimePoint m_startTime = Clock::now();

    // --- Interface data (protected by m_dataMutex) --------------------------
    struct InterfacePrevData {
        uint64_t bytesIn    = 0;
        uint64_t bytesOut   = 0;
        uint64_t packetsIn  = 0;
        uint64_t packetsOut = 0;
        uint64_t errorsIn   = 0;
        uint64_t errorsOut  = 0;
        uint64_t discardsIn = 0;
        uint64_t discardsOut = 0;
    };
    TimePoint m_lastInterfaceUpdate{};
    std::map<uint32_t, InterfacePrevData> m_prevInterfaceData;

    NetworkGlobalStats                m_globalStats{};
    std::vector<NetworkInterfaceStats> m_interfaceStats;

    // --- Process data (protected by m_dataMutex) ----------------------------
    std::unordered_map<uint32_t, ProcessNetworkUsage> m_processUsage;

    struct ProcessNameCacheEntry {
        std::wstring name;
        TimePoint    cachedAt;
    };
    std::unordered_map<uint32_t, ProcessNameCacheEntry> m_processNameCache;

    // --- Beaconing detection (protected by m_dataMutex) ---------------------
    struct BeaconTracker {
        std::vector<TimePoint> timestamps;
        size_t writePos = 0;
        size_t count    = 0;
        bool   alerted  = false;
    };
    std::unordered_map<std::string, BeaconTracker> m_beaconTrackers;

    // --- Connection delta tracking (protected by m_dataMutex) ---------------
    std::unordered_set<std::string>            m_previousConnectionSet;
    std::unordered_map<uint32_t, uint32_t>     m_perProcessNewConns;

    // --- Alert system (protected by m_alertMutex) ---------------------------
    std::vector<NetworkAlertCallback>          m_alertCallbacks;
    std::deque<NetworkAlert>                   m_recentAlerts;
    std::unordered_map<uint64_t, TimePoint>    m_alertCooldowns;
};

// ============================================================================
// PUBLIC INTERFACE — delegates to PIMPL
// ============================================================================

NetworkPerformanceMonitor& NetworkPerformanceMonitor::Instance() noexcept {
    static NetworkPerformanceMonitor instance;
    return instance;
}

NetworkPerformanceMonitor::NetworkPerformanceMonitor()
    : m_impl(std::make_unique<NetworkPerformanceMonitorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

NetworkPerformanceMonitor::~NetworkPerformanceMonitor() {
    m_impl->Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
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

void NetworkPerformanceMonitor::RegisterAlertCallback(NetworkAlertCallback callback) {
    m_impl->RegisterAlertCallback(std::move(callback));
}

void NetworkPerformanceMonitor::ClearAlertCallbacks() {
    m_impl->ClearAlertCallbacks();
}

std::vector<NetworkAlert> NetworkPerformanceMonitor::GetRecentAlerts(size_t maxCount) const {
    return m_impl->GetRecentAlerts(maxCount);
}

NetworkMonitorModuleStats NetworkPerformanceMonitor::GetModuleStats() const {
    return m_impl->GetModuleStats();
}

bool NetworkPerformanceMonitor::SelfTest() {
    return m_impl->SelfTest();
}

std::string NetworkPerformanceMonitor::GetVersionString() noexcept {
    return "4.0.0";
}

} // namespace Performance
} // namespace ShadowStrike
