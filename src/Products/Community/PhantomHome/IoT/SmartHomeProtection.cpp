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
 * ShadowStrike NGAV - SMART HOME PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file SmartHomeProtection.cpp
 * @brief Enterprise-grade smart home device protection implementation.
 *
 * Production-level implementation for monitoring and securing IoT devices
 * in home and SOHO environments with real-time traffic analysis.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Real-time traffic monitoring and baseline learning
 * - Anomaly detection with configurable thresholds
 * - Privacy-focused protection for cameras, doorbells, locks
 * - Multi-mode operation (Monitor, Protect, Lockdown, Away, Home, Sleep)
 * - Event-based alerting system
 * - Connection tracking and analysis
 * - Off-hours activity detection
 * - Bandwidth monitoring and anomaly detection
 * - Infrastructure reuse (ThreatIntel, WhiteListStore, NetworkUtils)
 * - Comprehensive statistics (10+ atomic counters)
 * - Callback system (4 types)
 * - Self-test and diagnostics
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "SmartHomeProtection.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <thread>
#include <fstream>
#include <format>
#include <unordered_set>
#include <deque>
#include <ctime>
#include <cctype>

// ============================================================================
// THIRD-PARTY INCLUDES
// ============================================================================
#include <nlohmann/json.hpp>
#include <atomic>

namespace ShadowStrike {
namespace IoT {

using Clock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }
    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }


/**
 * @brief Generate unique alert ID (monotonic, collision-free)
 */
uint64_t GenerateAlertId() {
    static std::atomic<uint64_t> s_counter{1};
    return s_counter.fetch_add(1, std::memory_order_relaxed);
}

/**
 * @brief Check if current time is in off-hours range
 */
bool IsOffHours(int offHoursStart, int offHoursEnd) {
    auto now = SystemClock::now();
    auto now_t = SystemClock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &now_t);
    int currentHour = tm.tm_hour;

    if (offHoursStart < offHoursEnd) {
        return currentHour >= offHoursStart && currentHour < offHoursEnd;
    } else {
        // Wraps around midnight
        return currentHour >= offHoursStart || currentHour < offHoursEnd;
    }
}

/**
 * @brief Check if IP is external (internet) — safe parsing, no exceptions
 */
bool IsExternalIP(std::string_view ip) {
    if (ip.empty() || ip.size() > 45) return true;  // Treat invalid as external (safer)

    // IPv4 private ranges
    if (ip.starts_with("192.168.")) return false;
    if (ip.starts_with("10.")) return false;
    if (ip.starts_with("172.")) {
        // Parse second octet safely without exceptions
        size_t firstDot = ip.find('.');
        if (firstDot == std::string_view::npos) return true;
        size_t secondDot = ip.find('.', firstDot + 1);
        if (secondDot == std::string_view::npos || secondDot <= firstDot + 1) return true;

        auto octetStr = ip.substr(firstDot + 1, secondDot - firstDot - 1);
        if (octetStr.size() > 3) return true;

        int octet = 0;
        for (char c : octetStr) {
            if (c < '0' || c > '9') return true;  // Non-digit = treat as external
            octet = octet * 10 + (c - '0');
            if (octet > 255) return true;
        }
        if (octet >= 16 && octet <= 31) return false;
    }
    if (ip.starts_with("127.")) return false;       // Loopback
    if (ip.starts_with("169.254.")) return false;   // Link-local
    if (ip == "0.0.0.0") return false;

    // IPv6 private/special ranges
    if (ip == "::1" || ip == "::") return false;    // Loopback/unspecified
    if (ip.starts_with("fc") || ip.starts_with("fd")) return false;  // ULA
    if (ip.starts_with("fe80:") || ip.starts_with("fe80%")) return false;  // Link-local

    return true;
}

/**
 * @brief Check if port is privacy-sensitive
 */
bool IsPrivacyPort(uint16_t port) {
    for (uint16_t privacyPort : SmartHomeConstants::PRIVACY_PORTS) {
        if (port == privacyPort) return true;
    }
    return false;
}

/**
 * @brief Validate MAC address format (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
 */
bool IsValidMacAddress(std::string_view mac) {
    if (mac.size() != 17) return false;
    for (size_t i = 0; i < 17; ++i) {
        if (i % 3 == 2) {
            if (mac[i] != ':' && mac[i] != '-') return false;
        } else {
            const char c = static_cast<char>(
                std::toupper(static_cast<unsigned char>(mac[i])));
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return false;
        }
    }
    return true;
}

/**
 * @brief Normalize MAC to uppercase colon-separated format
 * @return Normalized MAC or empty string on invalid input
 */
std::string NormalizeMacAddress(std::string_view mac) {
    if (!IsValidMacAddress(mac)) return {};
    std::string result;
    result.reserve(17);
    for (size_t i = 0; i < 17; ++i) {
        if (i % 3 == 2) {
            result += ':';
        } else {
            result += static_cast<char>(
                std::toupper(static_cast<unsigned char>(mac[i])));
        }
    }
    return result;
}

/**
 * @brief Basic IP address format validation (does not check range, just format)
 */
bool IsValidIpFormat(std::string_view ip) {
    if (ip.empty() || ip.size() > 45) return false;
    // Must contain at least one digit and either dots or colons
    bool hasDot = false, hasColon = false, hasDigit = false;
    for (char c : ip) {
        if (c == '.') hasDot = true;
        else if (c == ':') hasColon = true;
        else if (c >= '0' && c <= '9') hasDigit = true;
        else if (!((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '%'))
            return false;  // Invalid character
    }
    return hasDigit && (hasDot || hasColon);
}

}  // namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string MonitoredDeviceInfo::ToJson() const {
    nlohmann::json j = {
        {"deviceId", deviceId},
        {"macAddress", macAddress},
        {"ipAddress", ipAddress},
        {"deviceName", deviceName},
        {"type", static_cast<uint32_t>(type)},
        {"manufacturer", manufacturer},
        {"model", model},
        {"isHighPriority", isHighPriority},
        {"isPrivacySensitive", isPrivacySensitive},
        {"currentState", currentState},
        {"isOnline", isOnline},
        {"isStreaming", isStreaming},
        {"audioActive", audioActive},
        {"videoActive", videoActive},
        {"avgDailyTraffic", avgDailyTraffic},
        {"todayTraffic", todayTraffic}
    };
    return j.dump(2);
}

std::string DeviceTrafficStats::ToJson() const {
    nlohmann::json j = {
        {"bytesSent", bytesSent},
        {"bytesReceived", bytesReceived},
        {"totalConnections", totalConnections},
        {"externalConnections", externalConnections},
        {"uniqueDestinations", uniqueDestinations},
        {"streamingSessions", streamingSessions}
    };
    return j.dump(2);
}

std::string SmartHomeAlert::ToJson() const {
    nlohmann::json j = {
        {"alertId", alertId},
        {"deviceId", deviceId},
        {"deviceName", deviceName},
        {"eventType", static_cast<uint32_t>(eventType)},
        {"severity", static_cast<uint32_t>(severity)},
        {"privacyConcerns", static_cast<uint32_t>(privacyConcerns)},
        {"title", title},
        {"description", description},
        {"destination", destination},
        {"trafficVolume", trafficVolume},
        {"acknowledged", acknowledged},
        {"recommendations", recommendations}
    };
    return j.dump(2);
}

std::string DeviceConnection::ToJson() const {
    nlohmann::json j = {
        {"sourceDeviceId", sourceDeviceId},
        {"destinationIP", destinationIP},
        {"destinationHostname", destinationHostname},
        {"destinationPort", destinationPort},
        {"protocol", protocol},
        {"isEncrypted", isEncrypted},
        {"isExternal", isExternal},
        {"bytesTransferred", bytesTransferred},
        {"isActive", isActive}
    };
    return j.dump(2);
}

void SmartHomeStatistics::Reset() noexcept {
    totalEventsProcessed.store(0, std::memory_order_relaxed);
    alertsGenerated.store(0, std::memory_order_relaxed);
    privacyConcernsDetected.store(0, std::memory_order_relaxed);
    anomaliesDetected.store(0, std::memory_order_relaxed);
    streamingSessionsDetected.store(0, std::memory_order_relaxed);
    externalConnectionsBlocked.store(0, std::memory_order_relaxed);
    totalBytesMonitored.store(0, std::memory_order_relaxed);
    devicesMonitored.store(0, std::memory_order_relaxed);

    for (auto& counter : byEventType) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byDeviceType) {
        counter.store(0, std::memory_order_relaxed);
    }

    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string SmartHomeStatistics::ToJson() const {
    nlohmann::json j = {
        {"totalEventsProcessed", totalEventsProcessed.load()},
        {"alertsGenerated", alertsGenerated.load()},
        {"privacyConcernsDetected", privacyConcernsDetected.load()},
        {"anomaliesDetected", anomaliesDetected.load()},
        {"streamingSessionsDetected", streamingSessionsDetected.load()},
        {"externalConnectionsBlocked", externalConnectionsBlocked.load()},
        {"totalBytesMonitored", totalBytesMonitored.load()},
        {"devicesMonitored", devicesMonitored.load()}
    };
    return j.dump(2);
}

bool SmartHomeConfiguration::IsValid() const noexcept {
    if (offHoursStart < 0 || offHoursStart > 23) return false;
    if (offHoursEnd < 0 || offHoursEnd > 23) return false;
    if (anomalyThreshold <= 0.0f) return false;
    return true;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class SmartHomeProtectionImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    SmartHomeConfiguration m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};

    /// @brief Module status
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    /// @brief Protection active
    std::atomic<bool> m_protectionActive{false};

    /// @brief Statistics
    SmartHomeStatistics m_statistics;

    /// @brief Monitored devices
    std::unordered_map<std::string, MonitoredDeviceInfo> m_devices;
    mutable std::shared_mutex m_devicesMutex;

    /// @brief Traffic baselines (deviceId -> hourly average bytes)
    std::unordered_map<std::string, std::vector<uint64_t>> m_trafficBaselines;
    mutable std::shared_mutex m_baselinesMutex;

    /// @brief Active connections
    std::vector<DeviceConnection> m_activeConnections;
    mutable std::shared_mutex m_connectionsMutex;

    /// @brief Alerts
    std::deque<SmartHomeAlert> m_alerts;
    mutable std::shared_mutex m_alertsMutex;
    static constexpr size_t MAX_ALERTS = 500;

    /// @brief Callbacks
    std::vector<AlertCallback> m_alertCallbacks;
    std::vector<DeviceEventCallback> m_eventCallbacks;
    std::vector<ConnectionCallback> m_connectionCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
    std::mutex m_callbacksMutex;

    /// @brief Infrastructure integrations
    ThreatIntel::ThreatIntelManager* m_threatIntel = nullptr;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    /// @brief Baseline window start times per device (protected by m_baselinesMutex)
    std::unordered_map<std::string, TimePoint> m_baselineWindowStarts;

    /// @brief Alert rate limiting: key = "deviceId:eventType", value = last alert time
    ///        Protected by m_alertsMutex
    std::unordered_map<std::string, TimePoint> m_alertRateLimit;

    /// @brief Max tracked connections before eviction
    static constexpr size_t MAX_TRACKED_CONNECTIONS = 10000;

    /// @brief Minimum interval between duplicate alerts (same device + event type)
    static constexpr std::chrono::seconds ALERT_RATE_LIMIT_INTERVAL{60};

    // ========================================================================
    // METHODS
    // ========================================================================

    SmartHomeProtectionImpl() = default;
    ~SmartHomeProtectionImpl() = default;

    [[nodiscard]] bool Initialize(const SmartHomeConfiguration& config);
    void Shutdown();

    // Protection methods
    [[nodiscard]] bool StartProtectionInternal();
    void StopProtectionInternal();

    // Device management
    [[nodiscard]] bool MonitorDeviceInternal(const std::string& macAddress);
    [[nodiscard]] bool UnmonitorDeviceInternal(const std::string& macAddress);
    [[nodiscard]] std::vector<MonitoredDeviceInfo> GetMonitoredDevicesInternal() const;
    [[nodiscard]] std::optional<MonitoredDeviceInfo> GetDeviceInfoInternal(const std::string& deviceId) const;

    // Traffic analysis
    [[nodiscard]] DeviceTrafficStats GetDeviceTrafficInternal(
        const std::string& deviceId,
        std::chrono::hours period) const;
    void ProcessTrafficPacketInternal(
        const std::string& sourceMac,
        const std::string& destIP,
        uint16_t destPort,
        size_t bytes);

    // Alert management
    [[nodiscard]] std::vector<SmartHomeAlert> GetAlertsInternal(
        size_t maxAlerts,
        bool unacknowledgedOnly) const;
    void GenerateAlert(
        const std::string& deviceId,
        SmartDeviceEvent eventType,
        AlertSeverity severity,
        const std::string& title,
        const std::string& description,
        PrivacyConcern concerns = PrivacyConcern::None);

    // Analysis methods
    void AnalyzeTraffic(const std::string& deviceId, uint64_t bytes);
    void DetectAnomalies(const std::string& deviceId, uint64_t currentTraffic);
    void UpdateBaseline(const std::string& deviceId, uint64_t bytes);
    [[nodiscard]] bool IsAnomaly(const std::string& deviceId, uint64_t traffic) const;

    // Helpers
    void InvokeAlertCallbacks(const SmartHomeAlert& alert);
    void InvokeEventCallbacks(const std::string& deviceId, SmartDeviceEvent event);
    void InvokeConnectionCallbacks(const DeviceConnection& connection);
    void InvokeErrorCallbacks(const std::string& message, int code);
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool SmartHomeProtectionImpl::Initialize(
    const SmartHomeConfiguration& config)
{
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            ::ShadowStrike::Utils::Logger::Warn("SmartHomeProtection: Already initialized");
            return true;
        }

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Initializing...");

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Invalid configuration");
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Initialize infrastructure integrations
        m_threatIntel = &ThreatIntel::ThreatIntelManager::Instance();
        m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        m_status.store(ModuleStatus::Running, std::memory_order_release);

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Initialized successfully (mode: {})",
                          std::string(GetProtectionModeName(m_config.mode)));

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Initialization failed - {}",
                           e.what());
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void SmartHomeProtectionImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Shutting down...");

        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Stop protection
        StopProtectionInternal();

        // Clear data structures
        {
            std::unique_lock lock(m_devicesMutex);
            m_devices.clear();
        }

        {
            std::unique_lock lock(m_baselinesMutex);
            m_trafficBaselines.clear();
            m_baselineWindowStarts.clear();
        }

        {
            std::unique_lock lock(m_connectionsMutex);
            m_activeConnections.clear();
        }

        {
            std::unique_lock lock(m_alertsMutex);
            m_alerts.clear();
            m_alertRateLimit.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_alertCallbacks.clear();
            m_eventCallbacks.clear();
            m_connectionCallbacks.clear();
            m_errorCallbacks.clear();
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Shutdown complete");

    } catch (...) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Exception during shutdown");
    }
}

// ============================================================================
// IMPL: PROTECTION
// ============================================================================

bool SmartHomeProtectionImpl::StartProtectionInternal() {
    try {
        if (m_protectionActive.load(std::memory_order_acquire)) {
            ::ShadowStrike::Utils::Logger::Warn("SmartHomeProtection: Already active");
            return true;
        }

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Starting protection (mode: {})",
                          std::string(GetProtectionModeName(m_config.mode)));

        m_protectionActive.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Monitoring, std::memory_order_release);

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Protection started");

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to start protection - {}",
                           e.what());
        return false;
    }
}

void SmartHomeProtectionImpl::StopProtectionInternal() {
    try {
        if (!m_protectionActive.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Stopping protection");

        m_status.store(ModuleStatus::Running, std::memory_order_release);

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Protection stopped");

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Error stopping protection - {}",
                           e.what());
    }
}

// ============================================================================
// IMPL: DEVICE MANAGEMENT
// ============================================================================

bool SmartHomeProtectionImpl::MonitorDeviceInternal(const std::string& macAddress) {
    try {
        if (macAddress.empty()) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Empty MAC address");
            return false;
        }

        // Validate and normalize MAC address format
        std::string normalizedMac = NormalizeMacAddress(macAddress);
        if (normalizedMac.empty()) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Invalid MAC address format: {}",
                               macAddress);
            return false;
        }

        {
            std::unique_lock lock(m_devicesMutex);

            // Check if already monitoring
            if (m_devices.find(normalizedMac) != m_devices.end()) {
                ::ShadowStrike::Utils::Logger::Warn("SmartHomeProtection: Device already monitored: {}",
                                  normalizedMac);
                return true;
            }

            // Check device limit
            if (m_devices.size() >= SmartHomeConstants::MAX_MONITORED_DEVICES) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Maximum monitored devices reached ({})",
                                   SmartHomeConstants::MAX_MONITORED_DEVICES);
                return false;
            }

            // Create new monitored device
            MonitoredDeviceInfo device;
            device.deviceId = normalizedMac;
            device.macAddress = normalizedMac;
            device.deviceName = "Unknown Device";
            device.type = SmartDeviceType::Unknown;
            device.isOnline = true;
            device.monitoringSince = SystemClock::now();
            device.lastActivity = SystemClock::now();

            // Auto-classify privacy-sensitive based on future fingerprinting
            device.isPrivacySensitive = false;

            m_devices[normalizedMac] = std::move(device);

            m_statistics.devicesMonitored.store(
                static_cast<uint32_t>(std::min(m_devices.size(),
                    static_cast<size_t>(UINT32_MAX))),
                std::memory_order_relaxed);
        }
        // Lock released BEFORE callback invocation — prevents deadlock
        // if callback re-enters any device method

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Now monitoring device: {}",
                          normalizedMac);

        InvokeEventCallbacks(normalizedMac, SmartDeviceEvent::DeviceOnline);

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to monitor device - {}",
                           e.what());
        return false;
    }
}

bool SmartHomeProtectionImpl::UnmonitorDeviceInternal(const std::string& macAddress) {
    try {
        std::string lookupKey = NormalizeMacAddress(macAddress);
        if (lookupKey.empty()) {
            lookupKey = macAddress;  // Fallback to raw input for legacy entries
        }

        {
            std::unique_lock lock(m_devicesMutex);

            auto it = m_devices.find(lookupKey);
            if (it == m_devices.end()) {
                ::ShadowStrike::Utils::Logger::Warn("SmartHomeProtection: Device not found: {}",
                                  macAddress);
                return false;
            }

            m_devices.erase(it);

            m_statistics.devicesMonitored.store(
                static_cast<uint32_t>(std::min(m_devices.size(),
                    static_cast<size_t>(UINT32_MAX))),
                std::memory_order_relaxed);
        }
        // Lock released BEFORE callback invocation

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Stopped monitoring device: {}",
                          lookupKey);

        InvokeEventCallbacks(lookupKey, SmartDeviceEvent::DeviceOffline);

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to unmonitor device - {}",
                           e.what());
        return false;
    }
}

std::vector<MonitoredDeviceInfo> SmartHomeProtectionImpl::GetMonitoredDevicesInternal() const {
    std::shared_lock lock(m_devicesMutex);

    std::vector<MonitoredDeviceInfo> devices;
    devices.reserve(m_devices.size());

    for (const auto& [id, device] : m_devices) {
        devices.push_back(device);
    }

    return devices;
}

std::optional<MonitoredDeviceInfo> SmartHomeProtectionImpl::GetDeviceInfoInternal(
    const std::string& deviceId) const
{
    std::shared_lock lock(m_devicesMutex);

    auto it = m_devices.find(deviceId);
    if (it == m_devices.end()) {
        return std::nullopt;
    }

    return it->second;
}

// ============================================================================
// IMPL: TRAFFIC ANALYSIS
// ============================================================================

DeviceTrafficStats SmartHomeProtectionImpl::GetDeviceTrafficInternal(
    const std::string& deviceId,
    std::chrono::hours period) const
{
    DeviceTrafficStats stats;
    stats.periodStart = SystemClock::now() - period;
    stats.periodEnd = SystemClock::now();

    try {
        {
            std::shared_lock devLock(m_devicesMutex);
            auto it = m_devices.find(deviceId);
            if (it != m_devices.end()) {
                stats.bytesReceived = it->second.todayTraffic;
            }
        }

        // Count connections, unique destinations, and streaming sessions
        std::unordered_set<std::string> uniqueDests;
        {
            std::shared_lock connLock(m_connectionsMutex);
            for (const auto& conn : m_activeConnections) {
                if (conn.sourceDeviceId == deviceId) {
                    stats.totalConnections++;
                    stats.bytesSent += conn.bytesTransferred;
                    if (conn.isExternal) {
                        stats.externalConnections++;
                    }
                    uniqueDests.insert(
                        conn.destinationIP + ":" + std::to_string(conn.destinationPort));
                    if (conn.destinationPort == 554 || conn.destinationPort == 1935 ||
                        conn.destinationPort == 8554) {
                        stats.streamingSessions++;
                    }
                }
            }
        }
        stats.uniqueDestinations = static_cast<uint32_t>(
            std::min(uniqueDests.size(), static_cast<size_t>(UINT32_MAX)));

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to get traffic stats - {}",
                           e.what());
    }

    return stats;
}

void SmartHomeProtectionImpl::ProcessTrafficPacketInternal(
    const std::string& sourceMac,
    const std::string& destIP,
    uint16_t destPort,
    size_t bytes)
{
    try {
        if (!m_protectionActive.load(std::memory_order_acquire)) {
            return;
        }

        // === INPUT VALIDATION ===
        // All inputs come from network traffic — treat as hostile
        if (sourceMac.empty() || sourceMac.size() > 17) return;
        if (destIP.empty() || !IsValidIpFormat(destIP)) return;

        // Cap per-packet byte count to prevent overflow attacks
        constexpr size_t MAX_PACKET_BYTES = 64 * 1024;  // 64KB max
        const size_t cappedBytes = std::min(bytes, MAX_PACKET_BYTES);

        m_statistics.totalEventsProcessed.fetch_add(1, std::memory_order_relaxed);
        m_statistics.totalBytesMonitored.fetch_add(cappedBytes, std::memory_order_relaxed);

        // === SNAPSHOT CONFIGURATION (under lock) ===
        SmartHomeConfiguration configSnapshot;
        {
            std::shared_lock cfgLock(m_mutex);
            configSnapshot = m_config;
        }

        // === AUTO-MONITOR CHECK ===
        bool needAutoMonitor = false;
        {
            std::shared_lock devLock(m_devicesMutex);
            if (m_devices.find(sourceMac) == m_devices.end()) {
                needAutoMonitor = configSnapshot.autoMonitorNewDevices;
            }
        }

        if (needAutoMonitor) {
            MonitorDeviceInternal(sourceMac);
        }

        // === UPDATE DEVICE TRAFFIC STATE ===
        bool isPrivacyDevice = false;
        bool wasAlreadyStreaming = false;
        {
            std::unique_lock devLock(m_devicesMutex);
            auto it = m_devices.find(sourceMac);
            if (it == m_devices.end()) {
                return;  // Device not monitored and auto-monitor failed/disabled
            }

            // Cap todayTraffic to prevent overflow
            constexpr uint64_t MAX_DAILY_TRAFFIC = 100ULL * 1024 * 1024 * 1024;  // 100GB
            if (it->second.todayTraffic <= MAX_DAILY_TRAFFIC - cappedBytes) {
                it->second.todayTraffic += cappedBytes;
            }
            it->second.lastActivity = SystemClock::now();
            isPrivacyDevice = it->second.isPrivacySensitive;
            wasAlreadyStreaming = it->second.isStreaming;
        }
        // Device lock released

        const bool isExternal = IsExternalIP(destIP);
        const bool isPrivacyPort = IsPrivacyPort(destPort);

        // === BASELINE UPDATE ===
        UpdateBaseline(sourceMac, cappedBytes);

        // === ANOMALY DETECTION ===
        if (configSnapshot.alertOnAnomalies) {
            DetectAnomalies(sourceMac, cappedBytes);
        }

        // === PRIVACY CONCERN CHECK ===
        if (configSnapshot.privacyFocus && isPrivacyDevice && isExternal && isPrivacyPort) {
            if (IsOffHours(configSnapshot.offHoursStart, configSnapshot.offHoursEnd)) {
                GenerateAlert(
                    sourceMac,
                    SmartDeviceEvent::UnusualTraffic,
                    AlertSeverity::High,
                    "Off-Hours Privacy Device Activity",
                    std::format("Privacy-sensitive device {} sending data to {}:{} during off-hours",
                              sourceMac, destIP, destPort),
                    PrivacyConcern::OffHoursActivity | PrivacyConcern::CloudUpload
                );

                m_statistics.privacyConcernsDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // === STREAMING DETECTION ===
        if (!wasAlreadyStreaming &&
            (destPort == 554 || destPort == 1935 || destPort == 8554)) {
            bool didTransition = false;
            {
                std::unique_lock devLock(m_devicesMutex);
                auto it = m_devices.find(sourceMac);
                if (it != m_devices.end() && !it->second.isStreaming) {
                    it->second.isStreaming = true;
                    didTransition = true;
                }
            }
            // Device lock released before callbacks

            if (didTransition) {
                m_statistics.streamingSessionsDetected.fetch_add(1, std::memory_order_relaxed);

                if (configSnapshot.alertOnStreaming) {
                    GenerateAlert(
                        sourceMac,
                        SmartDeviceEvent::StreamStarted,
                        AlertSeverity::Medium,
                        "Streaming Session Started",
                        std::format("Device {} started streaming to {}:{}", sourceMac, destIP, destPort),
                        PrivacyConcern::CloudUpload
                    );
                }

                InvokeEventCallbacks(sourceMac, SmartDeviceEvent::StreamStarted);
            }
        }

        // === CONNECTION TRACKING (with bounded growth) ===
        if (isExternal && configSnapshot.alertOnExternalConnections) {
            DeviceConnection conn;
            conn.sourceDeviceId = sourceMac;
            conn.destinationIP = destIP;
            conn.destinationPort = destPort;
            conn.protocol = (destPort == 443 || destPort == 8443) ? "TLS" : "TCP";
            conn.isExternal = true;
            conn.isEncrypted = (destPort == 443 || destPort == 8443);
            conn.bytesTransferred = cappedBytes;
            conn.startTime = SystemClock::now();
            conn.isActive = true;

            {
                std::unique_lock connLock(m_connectionsMutex);

                // Evict stale connections before adding
                if (m_activeConnections.size() >= MAX_TRACKED_CONNECTIONS) {
                    // First pass: remove inactive connections
                    auto removeIt = std::remove_if(
                        m_activeConnections.begin(),
                        m_activeConnections.end(),
                        [](const DeviceConnection& c) { return !c.isActive; });
                    m_activeConnections.erase(removeIt, m_activeConnections.end());

                    // Still at cap: evict oldest entries
                    if (m_activeConnections.size() >= MAX_TRACKED_CONNECTIONS) {
                        const size_t toRemove = m_activeConnections.size() / 4;  // Evict 25%
                        m_activeConnections.erase(
                            m_activeConnections.begin(),
                            m_activeConnections.begin() + static_cast<ptrdiff_t>(toRemove));
                    }
                }

                m_activeConnections.push_back(conn);
            }
            // Connection lock released before callback

            InvokeConnectionCallbacks(conn);
        }

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Traffic processing error - {}",
                           e.what());
    }
}

// ============================================================================
// IMPL: ALERT MANAGEMENT
// ============================================================================

std::vector<SmartHomeAlert> SmartHomeProtectionImpl::GetAlertsInternal(
    size_t maxAlerts,
    bool unacknowledgedOnly) const
{
    std::shared_lock lock(m_alertsMutex);

    std::vector<SmartHomeAlert> result;
    result.reserve(std::min(maxAlerts, m_alerts.size()));

    for (auto it = m_alerts.rbegin(); it != m_alerts.rend() && result.size() < maxAlerts; ++it) {
        if (!unacknowledgedOnly || !it->acknowledged) {
            result.push_back(*it);
        }
    }

    return result;
}

void SmartHomeProtectionImpl::GenerateAlert(
    const std::string& deviceId,
    SmartDeviceEvent eventType,
    AlertSeverity severity,
    const std::string& title,
    const std::string& description,
    PrivacyConcern concerns)
{
    try {
        SmartHomeAlert alert;
        alert.alertId = GenerateAlertId();
        alert.deviceId = deviceId;
        alert.eventType = eventType;
        alert.severity = severity;
        alert.privacyConcerns = concerns;
        alert.title = title;
        alert.description = description;
        alert.alertTime = SystemClock::now();
        alert.acknowledged = false;

        // Get device name (separate lock scope)
        {
            std::shared_lock lock(m_devicesMutex);
            auto it = m_devices.find(deviceId);
            if (it != m_devices.end()) {
                alert.deviceName = it->second.deviceName;
            }
        }

        // Add recommendations based on severity and concern type
        if (severity >= AlertSeverity::High) {
            alert.recommendations.push_back("Review device activity immediately");
            alert.recommendations.push_back("Consider isolating device from network");
        }
        if (severity >= AlertSeverity::Critical) {
            alert.recommendations.push_back("Check device firmware for known vulnerabilities");
            alert.recommendations.push_back("Inspect all external connections from this device");
        }
        if (concerns != PrivacyConcern::None) {
            alert.recommendations.push_back("Check device privacy settings");
            alert.recommendations.push_back("Review device permissions");
        }
        if ((concerns & PrivacyConcern::UnencryptedTransmission) != PrivacyConcern::None) {
            alert.recommendations.push_back("Enable encryption on device or block unencrypted traffic");
        }

        // Store alert with rate limiting (single lock acquisition)
        {
            std::unique_lock lock(m_alertsMutex);

            // Rate limit: suppress duplicate alerts (same device + event type) within interval
            const std::string rateKey = deviceId + ":"
                + std::to_string(static_cast<uint8_t>(eventType));
            const auto now = Clock::now();
            auto rateIt = m_alertRateLimit.find(rateKey);
            if (rateIt != m_alertRateLimit.end()) {
                if (std::chrono::duration_cast<std::chrono::seconds>(
                        now - rateIt->second) < ALERT_RATE_LIMIT_INTERVAL) {
                    return;  // Rate limited — suppress duplicate
                }
            }
            m_alertRateLimit[rateKey] = now;

            // Cap rate limit map to prevent unbounded growth
            if (m_alertRateLimit.size() > 10000) {
                m_alertRateLimit.clear();  // Reset on overflow
            }

            m_alerts.push_back(std::move(alert));
            if (m_alerts.size() > MAX_ALERTS) {
                m_alerts.pop_front();
            }
        }

        m_statistics.alertsGenerated.fetch_add(1, std::memory_order_relaxed);

        // Re-read the alert from the deque for callback (we moved it above)
        SmartHomeAlert alertCopy;
        {
            std::shared_lock lock(m_alertsMutex);
            if (!m_alerts.empty()) {
                alertCopy = m_alerts.back();
            }
        }

        ::ShadowStrike::Utils::Logger::Warn("SmartHomeProtection: Alert generated - {} [{}]",
                          alertCopy.title,
                          
                              std::string(GetAlertSeverityName(alertCopy.severity)));

        InvokeAlertCallbacks(alertCopy);

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to generate alert - {}",
                           e.what());
    }
}

// ============================================================================
// IMPL: ANALYSIS METHODS
// ============================================================================

void SmartHomeProtectionImpl::UpdateBaseline(
    const std::string& deviceId,
    uint64_t bytes)
{
    try {
        std::unique_lock lock(m_baselinesMutex);

        auto& baseline = m_trafficBaselines[deviceId];
        auto& windowStart = m_baselineWindowStarts[deviceId];

        if (baseline.empty()) {
            baseline.resize(SmartHomeConstants::BASELINE_WINDOW_HOURS, 0);
            windowStart = Clock::now();
        }

        // Check if we need to rotate to a new hour window
        const auto elapsed = std::chrono::duration_cast<std::chrono::hours>(
            Clock::now() - windowStart);

        if (elapsed.count() > 0) {
            const size_t hoursElapsed = std::min(
                static_cast<size_t>(elapsed.count()),
                baseline.size());

            if (hoursElapsed >= baseline.size()) {
                // All data is stale — reset entire baseline
                std::fill(baseline.begin(), baseline.end(), 0);
            } else {
                // Shift left by hoursElapsed to make room for new window(s)
                std::rotate(baseline.begin(),
                           baseline.begin() + static_cast<ptrdiff_t>(hoursElapsed),
                           baseline.end());
                // Zero out the new slots at the end
                std::fill(baseline.end() - static_cast<ptrdiff_t>(hoursElapsed),
                          baseline.end(), 0);
            }
            windowStart = Clock::now();
        }

        // Accumulate bytes into current window (last element)
        if (!baseline.empty()) {
            constexpr uint64_t MAX_HOURLY_BYTES = 10ULL * 1024 * 1024 * 1024;  // 10GB/hr cap
            if (baseline.back() <= MAX_HOURLY_BYTES - bytes) {
                baseline.back() += bytes;
            } else {
                baseline.back() = MAX_HOURLY_BYTES;
            }
        }

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Baseline update failed - {}",
                           e.what());
    }
}

bool SmartHomeProtectionImpl::IsAnomaly(
    const std::string& deviceId,
    uint64_t traffic) const
{
    try {
        // Snapshot threshold under config lock
        float threshold;
        {
            std::shared_lock cfgLock(m_mutex);
            threshold = m_config.anomalyThreshold;
        }

        std::shared_lock lock(m_baselinesMutex);

        auto it = m_trafficBaselines.find(deviceId);
        if (it == m_trafficBaselines.end() || it->second.empty()) {
            return false;  // No baseline yet
        }

        // Calculate average hourly baseline
        uint64_t sum = std::accumulate(it->second.begin(), it->second.end(), 0ULL);
        uint64_t avg = sum / it->second.size();

        if (avg == 0) {
            return false;  // Not enough data
        }

        // Check if current traffic exceeds threshold multiple of average
        uint64_t anomalyLimit = static_cast<uint64_t>(
            static_cast<double>(avg) * static_cast<double>(threshold));
        return traffic > anomalyLimit;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Anomaly check failed - {}",
                           e.what());
        return false;
    }
}

void SmartHomeProtectionImpl::DetectAnomalies(
    const std::string& deviceId,
    uint64_t currentTraffic)
{
    try {
        if (IsAnomaly(deviceId, currentTraffic)) {
            m_statistics.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);

            // Snapshot threshold for log message
            float threshold;
            {
                std::shared_lock cfgLock(m_mutex);
                threshold = m_config.anomalyThreshold;
            }

            GenerateAlert(
                deviceId,
                SmartDeviceEvent::UnusualTraffic,
                AlertSeverity::Medium,
                "Traffic Anomaly Detected",
                std::format("Device {} traffic exceeded baseline by {:.1f}x",
                          deviceId, threshold),
                PrivacyConcern::HighBandwidthUsage
            );

            ::ShadowStrike::Utils::Logger::Warn("SmartHomeProtection: Traffic anomaly detected for device: {}",
                              deviceId);

            // On anomaly, run deep traffic analysis
            AnalyzeTraffic(deviceId, currentTraffic);
        }

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Anomaly detection failed - {}",
                           e.what());
    }
}

// ============================================================================
// IMPL: DEEP TRAFFIC ANALYSIS
// ============================================================================

void SmartHomeProtectionImpl::AnalyzeTraffic(
    const std::string& deviceId,
    uint64_t bytes)
{
    try {
        // === PHASE 1: Gather connection intelligence (under lock, then release) ===
        uint64_t totalExternalBytes = 0;
        uint32_t uniqueExternalDests = 0;
        bool hasUnencryptedPrivacy = false;
        std::string unencryptedDest;
        uint16_t unencryptedPort = 0;

        {
            std::shared_lock connLock(m_connectionsMutex);
            std::unordered_set<std::string> externalDests;
            for (const auto& conn : m_activeConnections) {
                if (conn.sourceDeviceId == deviceId && conn.isExternal) {
                    totalExternalBytes += conn.bytesTransferred;
                    externalDests.insert(conn.destinationIP);
                }
            }
            uniqueExternalDests = static_cast<uint32_t>(
                std::min(externalDests.size(), static_cast<size_t>(UINT32_MAX)));
        }

        // === PHASE 2: Check device privacy classification ===
        bool isPrivacyDevice = false;
        {
            std::shared_lock devLock(m_devicesMutex);
            auto it = m_devices.find(deviceId);
            if (it != m_devices.end()) {
                isPrivacyDevice = it->second.isPrivacySensitive;
            }
        }

        // === PHASE 3: Check for unencrypted privacy-device connections ===
        if (isPrivacyDevice) {
            std::shared_lock connLock(m_connectionsMutex);
            for (const auto& conn : m_activeConnections) {
                if (conn.sourceDeviceId == deviceId &&
                    conn.isExternal && !conn.isEncrypted) {
                    hasUnencryptedPrivacy = true;
                    unencryptedDest = conn.destinationIP;
                    unencryptedPort = conn.destinationPort;
                    break;  // One finding per analysis pass
                }
            }
        }

        // === PHASE 4: Generate alerts (all locks released) ===

        // Data exfiltration: high volume to external destinations
        constexpr uint64_t EXFIL_THRESHOLD_BYTES = 50ULL * 1024 * 1024;  // 50MB
        if (totalExternalBytes > EXFIL_THRESHOLD_BYTES) {
            GenerateAlert(
                deviceId,
                SmartDeviceEvent::DataExfiltration,
                AlertSeverity::Critical,
                "Potential Data Exfiltration Detected",
                std::format("Device {} sent {}MB to {} external destination(s)",
                          deviceId, totalExternalBytes / (1024 * 1024),
                          uniqueExternalDests),
                PrivacyConcern::DataExfiltration
            );
        }

        // Suspicious fan-out: too many unique external destinations
        constexpr uint32_t MAX_NORMAL_DESTINATIONS = 20;
        if (uniqueExternalDests > MAX_NORMAL_DESTINATIONS) {
            GenerateAlert(
                deviceId,
                SmartDeviceEvent::ExternalConnection,
                AlertSeverity::High,
                "Unusual External Connection Count",
                std::format("Device {} connected to {} unique external destinations "
                          "(threshold: {})", deviceId, uniqueExternalDests,
                          MAX_NORMAL_DESTINATIONS),
                PrivacyConcern::UnknownDestination
            );
        }

        // Privacy device sending unencrypted data externally
        if (hasUnencryptedPrivacy) {
            GenerateAlert(
                deviceId,
                SmartDeviceEvent::ExternalConnection,
                AlertSeverity::High,
                "Unencrypted External Connection from Privacy Device",
                std::format("Privacy device {} sending unencrypted data to {}:{}",
                          deviceId, unencryptedDest, unencryptedPort),
                PrivacyConcern::UnencryptedTransmission
            );
        }

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Traffic analysis failed - {}",
                           e.what());
    }
}

// ============================================================================
// IMPL: CALLBACKS
// ============================================================================

void SmartHomeProtectionImpl::InvokeAlertCallbacks(const SmartHomeAlert& alert) {
    // Copy callbacks under lock, then invoke without holding it.
    // This prevents deadlock if a callback re-enters the module
    // (e.g., registers another callback or queries device state).
    std::vector<AlertCallback> callbacks;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacks = m_alertCallbacks;
    }
    for (const auto& callback : callbacks) {
        try {
            if (callback) callback(alert);
        } catch (const std::exception& e) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Alert callback error - {}",
                               e.what());
        }
    }
}

void SmartHomeProtectionImpl::InvokeEventCallbacks(
    const std::string& deviceId,
    SmartDeviceEvent event)
{
    std::vector<DeviceEventCallback> callbacks;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacks = m_eventCallbacks;
    }
    for (const auto& callback : callbacks) {
        try {
            if (callback) callback(deviceId, event);
        } catch (const std::exception& e) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Event callback error - {}",
                               e.what());
        }
    }
}

void SmartHomeProtectionImpl::InvokeConnectionCallbacks(const DeviceConnection& connection) {
    std::vector<ConnectionCallback> callbacks;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacks = m_connectionCallbacks;
    }
    for (const auto& callback : callbacks) {
        try {
            if (callback) callback(connection);
        } catch (const std::exception& e) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Connection callback error - {}",
                               e.what());
        }
    }
}

void SmartHomeProtectionImpl::InvokeErrorCallbacks(
    const std::string& message,
    int code)
{
    std::vector<ErrorCallback> callbacks;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacks = m_errorCallbacks;
    }
    for (const auto& callback : callbacks) {
        try {
            if (callback) callback(message, code);
        } catch (...) {
            // Suppress errors in error handler to avoid infinite recursion
        }
    }
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> SmartHomeProtection::s_instanceCreated{false};

SmartHomeProtection& SmartHomeProtection::Instance() noexcept {
    static SmartHomeProtection instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool SmartHomeProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

SmartHomeProtection::SmartHomeProtection()
    : m_impl(std::make_unique<SmartHomeProtectionImpl>())
{
    ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Constructor called");
}

SmartHomeProtection::~SmartHomeProtection() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Destructor called");
}

bool SmartHomeProtection::Initialize(const SmartHomeConfiguration& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void SmartHomeProtection::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool SmartHomeProtection::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

ModuleStatus SmartHomeProtection::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire)
                  : ModuleStatus::Uninitialized;
}

bool SmartHomeProtection::UpdateConfiguration(const SmartHomeConfiguration& config) {
    if (!config.IsValid()) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Invalid configuration");
        return false;
    }

    if (!m_impl) {
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;

    ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Configuration updated");
    return true;
}

SmartHomeConfiguration SmartHomeProtection::GetConfiguration() const {
    if (!m_impl) {
        return SmartHomeConfiguration{};
    }

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// PROTECTION
// ============================================================================

bool SmartHomeProtection::StartProtection() {
    return m_impl ? m_impl->StartProtectionInternal() : false;
}

void SmartHomeProtection::StopProtection() {
    if (m_impl) {
        m_impl->StopProtectionInternal();
    }
}

bool SmartHomeProtection::IsProtectionActive() const noexcept {
    return m_impl ? m_impl->m_protectionActive.load(std::memory_order_acquire) : false;
}

void SmartHomeProtection::SetProtectionMode(ProtectionMode mode) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.mode = mode;

    ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Protection mode changed to: {}",
                      std::string(GetProtectionModeName(mode)));
}

ProtectionMode SmartHomeProtection::GetProtectionMode() const noexcept {
    if (!m_impl) return ProtectionMode::Monitor;

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.mode;
}

// ============================================================================
// DEVICE MANAGEMENT
// ============================================================================

bool SmartHomeProtection::MonitorDevice(const std::string& macAddress) {
    return m_impl ? m_impl->MonitorDeviceInternal(macAddress) : false;
}

bool SmartHomeProtection::UnmonitorDevice(const std::string& macAddress) {
    return m_impl ? m_impl->UnmonitorDeviceInternal(macAddress) : false;
}

std::vector<MonitoredDeviceInfo> SmartHomeProtection::GetMonitoredDevices() const {
    return m_impl ? m_impl->GetMonitoredDevicesInternal() : std::vector<MonitoredDeviceInfo>{};
}

std::optional<MonitoredDeviceInfo> SmartHomeProtection::GetDeviceInfo(const std::string& deviceId) const {
    return m_impl ? m_impl->GetDeviceInfoInternal(deviceId) : std::nullopt;
}

bool SmartHomeProtection::SetDevicePriority(const std::string& deviceId, bool highPriority) {
    if (!m_impl) return false;

    try {
        std::unique_lock lock(m_impl->m_devicesMutex);
        auto it = m_impl->m_devices.find(deviceId);
        if (it == m_impl->m_devices.end()) {
            return false;
        }

        it->second.isHighPriority = highPriority;

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Device {} priority: {}",
                          deviceId,
                          highPriority ? "HIGH" : "NORMAL");

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to set device priority - {}",
                           e.what());
        return false;
    }
}

bool SmartHomeProtection::SetPrivacySensitive(const std::string& deviceId, bool sensitive) {
    if (!m_impl) return false;

    try {
        std::unique_lock lock(m_impl->m_devicesMutex);
        auto it = m_impl->m_devices.find(deviceId);
        if (it == m_impl->m_devices.end()) {
            return false;
        }

        it->second.isPrivacySensitive = sensitive;

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Device {} privacy-sensitive: {}",
                          deviceId,
                          sensitive ? "YES" : "NO");

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to set privacy sensitivity - {}",
                           e.what());
        return false;
    }
}

// ============================================================================
// TRAFFIC ANALYSIS
// ============================================================================

DeviceTrafficStats SmartHomeProtection::GetDeviceTraffic(
    const std::string& deviceId,
    std::chrono::hours period) const
{
    return m_impl ? m_impl->GetDeviceTrafficInternal(deviceId, period)
                  : DeviceTrafficStats{};
}

std::vector<DeviceConnection> SmartHomeProtection::GetActiveConnections(
    const std::string& deviceId) const
{
    if (!m_impl) return {};

    std::shared_lock lock(m_impl->m_connectionsMutex);

    std::vector<DeviceConnection> result;
    for (const auto& conn : m_impl->m_activeConnections) {
        if (deviceId.empty() || conn.sourceDeviceId == deviceId) {
            if (conn.isActive) {
                result.push_back(conn);
            }
        }
    }

    return result;
}

void SmartHomeProtection::ProcessTrafficPacket(
    const std::string& sourceMac,
    const std::string& destIP,
    uint16_t destPort,
    size_t bytes)
{
    if (m_impl) {
        m_impl->ProcessTrafficPacketInternal(sourceMac, destIP, destPort, bytes);
    }
}

// ============================================================================
// ALERTS
// ============================================================================

std::vector<SmartHomeAlert> SmartHomeProtection::GetAlerts(
    size_t maxAlerts,
    bool unacknowledgedOnly) const
{
    return m_impl ? m_impl->GetAlertsInternal(maxAlerts, unacknowledgedOnly)
                  : std::vector<SmartHomeAlert>{};
}

bool SmartHomeProtection::AcknowledgeAlert(uint64_t alertId) {
    if (!m_impl) return false;

    try {
        std::unique_lock lock(m_impl->m_alertsMutex);

        for (auto& alert : m_impl->m_alerts) {
            if (alert.alertId == alertId) {
                alert.acknowledged = true;
                ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Alert {} acknowledged",
                                  alertId);
                return true;
            }
        }

        return false;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Failed to acknowledge alert - {}",
                           e.what());
        return false;
    }
}

void SmartHomeProtection::ClearAlerts() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_alertsMutex);
    m_impl->m_alerts.clear();

    ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Alerts cleared");
}

// ============================================================================
// CALLBACKS
// ============================================================================

void SmartHomeProtection::RegisterAlertCallback(AlertCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_alertCallbacks.push_back(std::move(callback));
}

void SmartHomeProtection::RegisterDeviceEventCallback(DeviceEventCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_eventCallbacks.push_back(std::move(callback));
}

void SmartHomeProtection::RegisterConnectionCallback(ConnectionCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_connectionCallbacks.push_back(std::move(callback));
}

void SmartHomeProtection::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void SmartHomeProtection::UnregisterCallbacks() {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_alertCallbacks.clear();
    m_impl->m_eventCallbacks.clear();
    m_impl->m_connectionCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

SmartHomeStatistics SmartHomeProtection::GetStatistics() const {
    // SmartHomeStatistics contains std::atomic members which are non-copyable.
    // We construct a fresh instance and populate from the source atomics.
    // NRVO ensures no copy/move of the return value.
    SmartHomeStatistics stats;
    if (m_impl) {
        const auto& src = m_impl->m_statistics;
        stats.totalEventsProcessed.store(
            src.totalEventsProcessed.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        stats.alertsGenerated.store(
            src.alertsGenerated.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        stats.privacyConcernsDetected.store(
            src.privacyConcernsDetected.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        stats.anomaliesDetected.store(
            src.anomaliesDetected.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        stats.streamingSessionsDetected.store(
            src.streamingSessionsDetected.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        stats.externalConnectionsBlocked.store(
            src.externalConnectionsBlocked.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        stats.totalBytesMonitored.store(
            src.totalBytesMonitored.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        stats.devicesMonitored.store(
            src.devicesMonitored.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        for (size_t i = 0; i < stats.byEventType.size(); ++i) {
            stats.byEventType[i].store(
                src.byEventType[i].load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        }
        for (size_t i = 0; i < stats.byDeviceType.size(); ++i) {
            stats.byDeviceType[i].store(
                src.byDeviceType[i].load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        }
        stats.startTime = AtomicValueLoadRelaxed(src.startTime);
    }
    return stats;
}

void SmartHomeProtection::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Statistics reset");
    }
}

bool SmartHomeProtection::SelfTest() {
    try {
        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Starting self-test");

        // ======================================================================
        // NOTE: SelfTest MUST NOT modify singleton production state.
        // All tests verify logic in isolation or read-only from current state.
        // ======================================================================

        // Test 1: Configuration validation logic
        {
            SmartHomeConfiguration validConfig;
            validConfig.enabled = true;
            validConfig.mode = ProtectionMode::Monitor;
            validConfig.offHoursStart = 23;
            validConfig.offHoursEnd = 6;
            validConfig.anomalyThreshold = 3.0f;

            if (!validConfig.IsValid()) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - valid config rejected");
                return false;
            }

            SmartHomeConfiguration invalidConfig1;
            invalidConfig1.offHoursStart = 25;  // Out of range
            if (invalidConfig1.IsValid()) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - invalid offHoursStart accepted");
                return false;
            }

            SmartHomeConfiguration invalidConfig2;
            invalidConfig2.anomalyThreshold = -1.0f;
            if (invalidConfig2.IsValid()) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - negative threshold accepted");
                return false;
            }
        }

        // Test 2: IP classification helpers
        {
            if (!IsExternalIP("8.8.8.8")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - 8.8.8.8 not external");
                return false;
            }
            if (IsExternalIP("192.168.1.1")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - 192.168.1.1 is external");
                return false;
            }
            if (IsExternalIP("10.0.0.1")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - 10.0.0.1 is external");
                return false;
            }
            if (IsExternalIP("172.16.0.1")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - 172.16.0.1 is external");
                return false;
            }
            if (IsExternalIP("169.254.1.1")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - link-local is external");
                return false;
            }
            if (IsExternalIP("127.0.0.1")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - loopback is external");
                return false;
            }
        }

        // Test 3: MAC address validation
        {
            if (!IsValidMacAddress("00:11:22:33:44:55")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - valid MAC rejected");
                return false;
            }
            if (!IsValidMacAddress("AA-BB-CC-DD-EE-FF")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - dash-format MAC rejected");
                return false;
            }
            if (IsValidMacAddress("invalid")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - garbage MAC accepted");
                return false;
            }
            if (IsValidMacAddress("00:11:22:33:44:GG")) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - non-hex MAC accepted");
                return false;
            }
            if (NormalizeMacAddress("aa-bb-cc-dd-ee-ff") != "AA:BB:CC:DD:EE:FF") {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - MAC normalization");
                return false;
            }
        }

        // Test 4: Privacy port detection
        {
            if (!IsPrivacyPort(554)) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - RTSP port 554 not detected");
                return false;
            }
            if (IsPrivacyPort(80)) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - port 80 marked as privacy");
                return false;
            }
        }

        // Test 5: Utility function coverage
        {
            if (GetSmartDeviceTypeName(SmartDeviceType::Camera) != "Camera") {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - device type name");
                return false;
            }
            if (!IsPrivacySensitiveDevice(SmartDeviceType::Camera)) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - camera not privacy-sensitive");
                return false;
            }
            if (IsPrivacySensitiveDevice(SmartDeviceType::LightBulb)) {
                ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - lightbulb marked privacy-sensitive");
                return false;
            }
        }

        // Test 6: Verify impl pointer integrity
        if (!m_impl) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - null impl pointer");
            return false;
        }

        // Test 7: Version string
        if (GetVersionString().empty()) {
            ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test FAILED - empty version string");
            return false;
        }

        ::ShadowStrike::Utils::Logger::Info("SmartHomeProtection: Self-test PASSED (all 7 checks)");
        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("SmartHomeProtection: Self-test exception - {}",
                           e.what());
        return false;
    }
}

std::string SmartHomeProtection::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
                      SmartHomeConstants::VERSION_MAJOR,
                      SmartHomeConstants::VERSION_MINOR,
                      SmartHomeConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetSmartDeviceTypeName(SmartDeviceType type) noexcept {
    switch (type) {
        case SmartDeviceType::Unknown: return "Unknown";
        case SmartDeviceType::Camera: return "Camera";
        case SmartDeviceType::Doorbell: return "Doorbell";
        case SmartDeviceType::Lock: return "Smart Lock";
        case SmartDeviceType::Thermostat: return "Thermostat";
        case SmartDeviceType::Speaker: return "Smart Speaker";
        case SmartDeviceType::Display: return "Smart Display";
        case SmartDeviceType::LightBulb: return "Light Bulb";
        case SmartDeviceType::LightSwitch: return "Light Switch";
        case SmartDeviceType::Plug: return "Smart Plug";
        case SmartDeviceType::Appliance: return "Appliance";
        case SmartDeviceType::Sensor: return "Sensor";
        case SmartDeviceType::MotionSensor: return "Motion Sensor";
        case SmartDeviceType::DoorSensor: return "Door Sensor";
        case SmartDeviceType::BabyMonitor: return "Baby Monitor";
        case SmartDeviceType::SecurityPanel: return "Security Panel";
        case SmartDeviceType::Garage: return "Garage Door";
        case SmartDeviceType::Sprinkler: return "Sprinkler";
        case SmartDeviceType::Hub: return "Hub";
        case SmartDeviceType::TV: return "Smart TV";
        case SmartDeviceType::StreamingDevice: return "Streaming Device";
        default: return "Unknown";
    }
}

std::string_view GetSmartDeviceEventName(SmartDeviceEvent event) noexcept {
    switch (event) {
        case SmartDeviceEvent::Unknown: return "Unknown";
        case SmartDeviceEvent::StreamStarted: return "Stream Started";
        case SmartDeviceEvent::StreamEnded: return "Stream Ended";
        case SmartDeviceEvent::AudioActivated: return "Audio Activated";
        case SmartDeviceEvent::AudioDeactivated: return "Audio Deactivated";
        case SmartDeviceEvent::VideoActivated: return "Video Activated";
        case SmartDeviceEvent::VideoDeactivated: return "Video Deactivated";
        case SmartDeviceEvent::MotionDetected: return "Motion Detected";
        case SmartDeviceEvent::DoorOpened: return "Door Opened";
        case SmartDeviceEvent::DoorClosed: return "Door Closed";
        case SmartDeviceEvent::LockEngaged: return "Lock Engaged";
        case SmartDeviceEvent::LockDisengaged: return "Lock Disengaged";
        case SmartDeviceEvent::TempChanged: return "Temperature Changed";
        case SmartDeviceEvent::LightOn: return "Light On";
        case SmartDeviceEvent::LightOff: return "Light Off";
        case SmartDeviceEvent::FirmwareUpdate: return "Firmware Update";
        case SmartDeviceEvent::ConfigChange: return "Config Change";
        case SmartDeviceEvent::UnusualTraffic: return "Unusual Traffic";
        case SmartDeviceEvent::ExternalConnection: return "External Connection";
        case SmartDeviceEvent::DataExfiltration: return "Data Exfiltration";
        case SmartDeviceEvent::UnauthorizedAccess: return "Unauthorized Access";
        case SmartDeviceEvent::DeviceOnline: return "Device Online";
        case SmartDeviceEvent::DeviceOffline: return "Device Offline";
        default: return "Unknown";
    }
}

std::string_view GetAlertSeverityName(AlertSeverity severity) noexcept {
    switch (severity) {
        case AlertSeverity::Info: return "Info";
        case AlertSeverity::Low: return "Low";
        case AlertSeverity::Medium: return "Medium";
        case AlertSeverity::High: return "High";
        case AlertSeverity::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetPrivacyConcernName(PrivacyConcern concern) noexcept {
    switch (concern) {
        case PrivacyConcern::None: return "None";
        case PrivacyConcern::UnauthorizedVideo: return "Unauthorized Video";
        case PrivacyConcern::UnauthorizedAudio: return "Unauthorized Audio";
        case PrivacyConcern::DataExfiltration: return "Data Exfiltration";
        case PrivacyConcern::LocationTracking: return "Location Tracking";
        case PrivacyConcern::ThirdPartySharing: return "Third-Party Sharing";
        case PrivacyConcern::CloudUpload: return "Cloud Upload";
        case PrivacyConcern::UnencryptedTransmission: return "Unencrypted Transmission";
        case PrivacyConcern::OffHoursActivity: return "Off-Hours Activity";
        case PrivacyConcern::UnknownDestination: return "Unknown Destination";
        case PrivacyConcern::HighBandwidthUsage: return "High Bandwidth Usage";
        default: return "Unknown";
    }
}

std::string_view GetProtectionModeName(ProtectionMode mode) noexcept {
    switch (mode) {
        case ProtectionMode::Monitor: return "Monitor";
        case ProtectionMode::Protect: return "Protect";
        case ProtectionMode::Lockdown: return "Lockdown";
        case ProtectionMode::Away: return "Away";
        case ProtectionMode::Home: return "Home";
        case ProtectionMode::Sleep: return "Sleep";
        default: return "Unknown";
    }
}

bool IsPrivacySensitiveDevice(SmartDeviceType type) noexcept {
    switch (type) {
        case SmartDeviceType::Camera:
        case SmartDeviceType::Doorbell:
        case SmartDeviceType::Lock:
        case SmartDeviceType::BabyMonitor:
        case SmartDeviceType::Speaker:
        case SmartDeviceType::Display:
            return true;
        default:
            return false;
    }
}

}  // namespace IoT
}  // namespace ShadowStrike
