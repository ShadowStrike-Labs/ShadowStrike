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
 * ShadowStrike NGAV - NETWORK PERFORMANCE MONITORING MODULE
 * ============================================================================
 *
 * @file NetworkPerformanceMonitor.hpp
 * @brief Enterprise-grade network traffic analysis and performance monitoring.
 *
 * Provides real-time visibility into network throughput, active connections,
 * and per-process bandwidth usage. Essential for detecting C2 communications,
 * data exfiltration, and network anomalies.
 *
 * CAPABILITIES:
 * =============
 * 1. TRAFFIC METRICS
 *    - System-wide throughput (Ingress/Egress) with rate calculation
 *    - Per-interface statistics including error/discard rates
 *    - Packet rates, counter-rollover-safe delta computation
 *
 * 2. CONNECTION TRACKING (IPv4 + IPv6)
 *    - Active TCP/UDP connection enumeration via IP Helper
 *    - State analysis (ESTABLISHED, LISTENING, TIME_WAIT, etc.)
 *    - Per-process connection mapping with PID attribution
 *
 * 3. PROCESS ATTRIBUTION
 *    - Connection count per process (TCP v4/v6, UDP v4/v6)
 *    - Top talker identification sorted by total connections
 *    - Process name caching with TTL to avoid repeated handle opens
 *
 * 4. ANOMALY / THREAT DETECTION
 *    - C2 Beaconing: regular-interval connections to same destination
 *    - Data Exfiltration: cumulative outbound connection tracking
 *    - Connection Flooding: rapid new-connection bursts per process
 *    - Interface Health: error/discard rate spike detection
 *    - High Bandwidth: aggregate throughput threshold alerts
 *
 * 5. ALERT SYSTEM
 *    - Callback registration for real-time alert delivery
 *    - Rate-limited alert emission to prevent alert storms
 *    - Recent alert ring buffer for diagnostic queries
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: AGPL-3.0 — ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <map>
#include <optional>
#include <functional>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================
#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
namespace ShadowStrike::Performance {
    class NetworkPerformanceMonitorImpl;
}

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// CONSTANTS
// ============================================================================
namespace NetworkConstants {
    constexpr uint32_t DEFAULT_POLLING_INTERVAL_MS  = 1000;
    constexpr uint32_t MIN_POLLING_INTERVAL_MS      = 100;
    constexpr uint32_t MAX_POLLING_INTERVAL_MS      = 60000;

    constexpr uint32_t MAX_TRACKED_PROCESSES        = 4096;
    constexpr uint32_t MAX_TRACKED_DESTINATIONS     = 16384;
    constexpr uint32_t MAX_TABLE_ALLOC_BYTES        = 64u * 1024u * 1024u;  // 64 MiB cap

    constexpr uint32_t BEACONING_HISTORY_SIZE       = 64;
    constexpr uint32_t BEACONING_MIN_SAMPLES        = 5;
    constexpr double   BEACONING_JITTER_THRESHOLD   = 0.15;   // CoV < 15 % ⇒ suspicious

    constexpr uint64_t EXFIL_DEFAULT_THRESHOLD_BYTES = 100ULL * 1024 * 1024;  // 100 MiB
    constexpr uint32_t FLOOD_DEFAULT_THRESHOLD       = 500;    // new conns / interval

    constexpr uint32_t PROCESS_NAME_CACHE_TTL_SEC    = 30;
    constexpr size_t   MAX_RECENT_ALERTS             = 200;
    constexpr uint32_t ALERT_COOLDOWN_SEC            = 60;
}

// ============================================================================
// TYPE ALIASES
// ============================================================================
using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

enum class NetworkAlertType : uint8_t {
    HighBandwidth       = 0,
    ConnectionFlood     = 1,
    SuspectedBeaconing  = 2,
    DataExfiltration    = 3,
    InterfaceErrors     = 4,
};

enum class NetworkAlertSeverity : uint8_t {
    Low      = 0,
    Medium   = 1,
    High     = 2,
    Critical = 3,
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief A single network alert emitted by the detection heuristics.
 */
struct NetworkAlert {
    NetworkAlertType     type{};
    NetworkAlertSeverity severity{};
    uint32_t             processId   = 0;
    std::wstring         processName;
    std::string          remoteAddress;
    uint16_t             remotePort  = 0;
    std::string          details;
    TimePoint            timestamp;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Network interface statistics with rate calculations.
 */
struct NetworkInterfaceStats {
    std::string interfaceName;
    std::string description;
    std::string macAddress;
    uint32_t    interfaceIndex = 0;

    // Rates (per second)
    double inboundBitsPerSec     = 0.0;
    double outboundBitsPerSec    = 0.0;
    double inboundPacketsPerSec  = 0.0;
    double outboundPacketsPerSec = 0.0;

    // Cumulative totals
    uint64_t totalBytesIn    = 0;
    uint64_t totalBytesOut   = 0;
    uint64_t totalPacketsIn  = 0;
    uint64_t totalPacketsOut = 0;
    uint64_t errorsIn        = 0;
    uint64_t errorsOut       = 0;
    uint64_t discardsIn      = 0;
    uint64_t discardsOut     = 0;

    // Error / discard rates (per second)
    double errorRateIn   = 0.0;
    double errorRateOut  = 0.0;
    double discardRateIn = 0.0;
    double discardRateOut = 0.0;

    // Status
    bool     isUp      = false;
    uint64_t speedBits = 0;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Per-process network usage metrics (IPv4 + IPv6).
 */
struct ProcessNetworkUsage {
    uint32_t     processId = 0;
    std::wstring processName;

    uint32_t tcpConnectionsV4 = 0;
    uint32_t tcpConnectionsV6 = 0;
    uint32_t udpListenersV4   = 0;
    uint32_t udpListenersV6   = 0;

    uint32_t establishedConnections = 0;
    uint32_t listeningPorts         = 0;

    // Detection flags (set by heuristic engines)
    bool suspectedBeaconing    = false;
    bool suspectedExfiltration = false;
    bool suspectedFlood        = false;

    [[nodiscard]] uint32_t TotalConnections() const noexcept {
        return tcpConnectionsV4 + tcpConnectionsV6 + udpListenersV4 + udpListenersV6;
    }

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief System-wide network statistics snapshot.
 */
struct NetworkGlobalStats {
    double   totalInboundBitsPerSec  = 0.0;
    double   totalOutboundBitsPerSec = 0.0;
    uint32_t totalTcpConnectionsV4   = 0;
    uint32_t totalTcpConnectionsV6   = 0;
    uint32_t totalUdpListenersV4     = 0;
    uint32_t totalUdpListenersV6     = 0;
    uint32_t activeInterfaces        = 0;
    uint64_t totalErrorsIn           = 0;
    uint64_t totalErrorsOut          = 0;
    uint64_t totalDiscardsIn         = 0;
    uint64_t totalDiscardsOut        = 0;
    TimePoint timestamp;

    [[nodiscard]] uint32_t TotalTcpConnections() const noexcept {
        return totalTcpConnectionsV4 + totalTcpConnectionsV6;
    }
    [[nodiscard]] uint32_t TotalUdpListeners() const noexcept {
        return totalUdpListenersV4 + totalUdpListenersV6;
    }
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration for the network monitor.
 */
struct NetworkMonitorConfig {
    bool     enabled                = true;
    uint32_t pollingIntervalMs      = NetworkConstants::DEFAULT_POLLING_INTERVAL_MS;
    bool     trackPerProcess        = true;
    bool     trackInterfaces        = true;

    // Detection toggles
    bool     detectBeaconing        = true;
    bool     detectExfiltration     = true;
    bool     detectConnectionFlood  = true;

    // Alert thresholds
    double   highBandwidthThresholdMbps  = 100.0;
    uint32_t connectionFloodThreshold    = NetworkConstants::FLOOD_DEFAULT_THRESHOLD;
    uint64_t exfiltrationThresholdBytes  = NetworkConstants::EXFIL_DEFAULT_THRESHOLD_BYTES;
    double   beaconingJitterThreshold    = NetworkConstants::BEACONING_JITTER_THRESHOLD;
    double   interfaceErrorRateThreshold = 100.0;   // errors/sec

    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Module health / diagnostic snapshot (plain values, no atomics).
 *
 * Returned by GetModuleStats().  The implementation stores atomics internally
 * and loads them into this copyable snapshot.
 */
struct NetworkMonitorModuleStats {
    uint64_t  cyclesCompleted        = 0;
    uint64_t  errorsEncountered      = 0;
    uint64_t  alertsTriggered        = 0;
    uint64_t  totalConnectionsTracked = 0;
    uint64_t  totalProcessesTracked  = 0;
    uint64_t  uptimeSeconds          = 0;

    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACKS
// ============================================================================

/**
 * @brief Callback invoked on each network alert.  Fired outside internal locks;
 *        implementations MUST NOT call back into NetworkPerformanceMonitor.
 */
using NetworkAlertCallback = std::function<void(const NetworkAlert& alert)>;

// ============================================================================
// NETWORK MONITOR CLASS
// ============================================================================

/**
 * @class NetworkPerformanceMonitor
 * @brief Meyers' Singleton — monitors system network activity and detects
 *        anomalies indicative of C2, exfiltration, and flooding.
 *
 * Thread-safe.  All public methods may be called from any thread.
 */
class NetworkPerformanceMonitor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    [[nodiscard]] static NetworkPerformanceMonitor& Instance() noexcept;

    // Non-copyable / non-movable
    NetworkPerformanceMonitor(const NetworkPerformanceMonitor&)            = delete;
    NetworkPerformanceMonitor& operator=(const NetworkPerformanceMonitor&) = delete;
    NetworkPerformanceMonitor(NetworkPerformanceMonitor&&)                 = delete;
    NetworkPerformanceMonitor& operator=(NetworkPerformanceMonitor&&)      = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    [[nodiscard]] bool Initialize(const NetworkMonitorConfig& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    void UpdateConfig(const NetworkMonitorConfig& config);
    [[nodiscard]] NetworkMonitorConfig GetConfig() const;

    // ========================================================================
    // DATA ACCESS
    // ========================================================================

    /** @brief Snapshot of system-wide network statistics. */
    [[nodiscard]] NetworkGlobalStats GetGlobalStats() const;

    /** @brief Statistics for all active (UP) interfaces. */
    [[nodiscard]] std::vector<NetworkInterfaceStats> GetInterfaceStats() const;

    /** @brief Top processes by total connection count. */
    [[nodiscard]] std::vector<ProcessNetworkUsage> GetTopProcesses(size_t count = 10) const;

    /** @brief Usage for a specific PID (nullopt if not tracked). */
    [[nodiscard]] std::optional<ProcessNetworkUsage> GetProcessUsage(uint32_t pid) const;

    // ========================================================================
    // ALERT MANAGEMENT
    // ========================================================================

    /** @brief Register a callback invoked on each emitted alert. */
    void RegisterAlertCallback(NetworkAlertCallback callback);

    /** @brief Remove all registered callbacks. */
    void ClearAlertCallbacks();

    /** @brief Return the last N alerts (most-recent first). */
    [[nodiscard]] std::vector<NetworkAlert> GetRecentAlerts(size_t maxCount = 50) const;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================
    [[nodiscard]] NetworkMonitorModuleStats GetModuleStats() const;
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    NetworkPerformanceMonitor();
    ~NetworkPerformanceMonitor();

    std::unique_ptr<NetworkPerformanceMonitorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

} // namespace Performance
} // namespace ShadowStrike
