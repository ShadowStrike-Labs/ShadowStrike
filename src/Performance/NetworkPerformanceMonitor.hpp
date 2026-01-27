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
 *    - System-wide throughput (Ingress/Egress)
 *    - Per-interface statistics
 *    - Packet rates and error counters
 *
 * 2. CONNECTION TRACKING
 *    - Active TCP/UDP connection counts
 *    - State analysis (ESTABLISHED, LISTENING, etc.)
 *    - Per-process connection mapping
 *
 * 3. PROCESS ATTRIBUTION
 *    - Bandwidth usage per process
 *    - Top talker identification
 *    - New connection detection
 *
 * 4. ANOMALY DETECTION
 *    - High bandwidth spikes
 *    - Connection flooding
 *    - Port scanning patterns
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
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
    constexpr uint32_t DEFAULT_POLLING_INTERVAL_MS = 1000;
    constexpr uint32_t MIN_POLLING_INTERVAL_MS = 100;
    constexpr uint32_t MAX_POLLING_INTERVAL_MS = 60000;
}

// ============================================================================
// TYPE ALIASES
// ============================================================================
using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Network interface statistics
 */
struct NetworkInterfaceStats {
    std::string interfaceName;
    std::string description;
    std::string macAddress;

    // Rates (per second)
    double inboundBitsPerSec = 0.0;
    double outboundBitsPerSec = 0.0;
    double inboundPacketsPerSec = 0.0;
    double outboundPacketsPerSec = 0.0;

    // Totals
    uint64_t totalBytesIn = 0;
    uint64_t totalBytesOut = 0;
    uint64_t errorsIn = 0;
    uint64_t errorsOut = 0;

    // Status
    bool isUp = false;
    uint64_t speedBits = 0; // Link speed

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Process network usage metrics
 */
struct ProcessNetworkUsage {
    uint32_t processId = 0;
    std::wstring processName;

    // Connections
    uint32_t tcpConnections = 0;
    uint32_t udpListeners = 0;

    // Usage (if available via ETW/NDIS)
    // Note: Standard user-mode APIs often don't provide per-process bandwidth
    // without ETW. We will track what is available.
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Global network statistics
 */
struct NetworkGlobalStats {
    double totalInboundBitsPerSec = 0.0;
    double totalOutboundBitsPerSec = 0.0;
    uint32_t totalTcpConnections = 0;
    uint32_t totalUdpListeners = 0;
    uint32_t activeInterfaces = 0;
    TimePoint timestamp;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct NetworkMonitorConfig {
    bool enabled = true;
    uint32_t pollingIntervalMs = NetworkConstants::DEFAULT_POLLING_INTERVAL_MS;
    bool trackPerProcess = true;
    bool trackInterfaces = true;

    // Alert thresholds
    double highBandwidthThresholdMbps = 100.0;
    uint32_t connectionFloodThreshold = 1000;

    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Module statistics
 */
struct NetworkMonitorModuleStats {
    std::atomic<uint64_t> cyclesCompleted{0};
    std::atomic<uint64_t> errorsEncountered{0};
    std::atomic<uint64_t> alertsTriggered{0};
    TimePoint startTime = Clock::now();

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACKS
// ============================================================================
using NetworkAlertCallback = std::function<void(const std::string& alertType, const std::string& details)>;

// ============================================================================
// NETWORK MONITOR CLASS
// ============================================================================

/**
 * @class NetworkPerformanceMonitor
 * @brief Singleton class for monitoring system network activity.
 */
class NetworkPerformanceMonitor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    [[nodiscard]] static NetworkPerformanceMonitor& Instance() noexcept;

    // Non-copyable/movable
    NetworkPerformanceMonitor(const NetworkPerformanceMonitor&) = delete;
    NetworkPerformanceMonitor& operator=(const NetworkPerformanceMonitor&) = delete;
    NetworkPerformanceMonitor(NetworkPerformanceMonitor&&) = delete;
    NetworkPerformanceMonitor& operator=(NetworkPerformanceMonitor&&) = delete;

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

    /**
     * @brief Get global network statistics
     */
    [[nodiscard]] NetworkGlobalStats GetGlobalStats() const;

    /**
     * @brief Get statistics for all active interfaces
     */
    [[nodiscard]] std::vector<NetworkInterfaceStats> GetInterfaceStats() const;

    /**
     * @brief Get top processes by connection count
     */
    [[nodiscard]] std::vector<ProcessNetworkUsage> GetTopProcesses(size_t count = 5) const;

    /**
     * @brief Get usage for specific process
     */
    [[nodiscard]] std::optional<ProcessNetworkUsage> GetProcessUsage(uint32_t pid) const;

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
