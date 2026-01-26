/**
 * @file DDosProtection.cpp
 * @brief Enterprise implementation of DDoS detection and mitigation engine.
 *
 * The Floodgate of ShadowStrike NGAV - protects against network denial-of-service
 * attacks through multi-layer detection, intelligent rate limiting, and automated
 * mitigation. Monitors traffic patterns, detects anomalies, and applies adaptive
 * defenses to maintain service availability under attack.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "DDosProtection.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ThreadPool.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <sstream>
#include <deque>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <WinSock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Network {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] constexpr const char* AttackTypeToString(AttackType type) noexcept {
    switch (type) {
        case AttackType::NONE: return "None";
        case AttackType::IP_FLOOD: return "IP Flood";
        case AttackType::IP_FRAGMENTATION: return "IP Fragmentation";
        case AttackType::ICMP_FLOOD: return "ICMP Flood";
        case AttackType::SMURF: return "Smurf Attack";
        case AttackType::SYN_FLOOD: return "SYN Flood";
        case AttackType::SYN_ACK_FLOOD: return "SYN-ACK Flood";
        case AttackType::ACK_FLOOD: return "ACK Flood";
        case AttackType::RST_FLOOD: return "RST Flood";
        case AttackType::FIN_FLOOD: return "FIN Flood";
        case AttackType::UDP_FLOOD: return "UDP Flood";
        case AttackType::REFLECTION: return "Reflection Attack";
        case AttackType::HTTP_GET_FLOOD: return "HTTP GET Flood";
        case AttackType::HTTP_POST_FLOOD: return "HTTP POST Flood";
        case AttackType::SLOWLORIS: return "Slowloris";
        case AttackType::SLOW_POST: return "Slow POST";
        case AttackType::HTTP_FRAGMENTED: return "HTTP Fragmented";
        case AttackType::DNS_QUERY_FLOOD: return "DNS Query Flood";
        case AttackType::DNS_AMPLIFICATION: return "DNS Amplification";
        case AttackType::DNS_REFLECTION: return "DNS Reflection";
        case AttackType::NTP_AMPLIFICATION: return "NTP Amplification";
        case AttackType::SSDP_AMPLIFICATION: return "SSDP Amplification";
        case AttackType::MEMCACHED_AMPLIFICATION: return "Memcached Amplification";
        case AttackType::CHARGEN_AMPLIFICATION: return "CharGen Amplification";
        case AttackType::LAND_ATTACK: return "Land Attack";
        case AttackType::TEARDROP: return "Teardrop Attack";
        case AttackType::PING_OF_DEATH: return "Ping of Death";
        case AttackType::SOCKSTRESS: return "Sockstress";
        case AttackType::MULTI_VECTOR: return "Multi-Vector Attack";
        case AttackType::UNKNOWN: return "Unknown";
        default: return "Unknown";
    }
}

[[nodiscard]] constexpr const char* AttackSeverityToString(AttackSeverity severity) noexcept {
    switch (severity) {
        case AttackSeverity::NONE: return "None";
        case AttackSeverity::LOW: return "Low";
        case AttackSeverity::MEDIUM: return "Medium";
        case AttackSeverity::HIGH: return "High";
        case AttackSeverity::CRITICAL: return "Critical";
        default: return "Unknown";
    }
}

[[nodiscard]] constexpr const char* MitigationActionToString(MitigationAction action) noexcept {
    switch (action) {
        case MitigationAction::NONE: return "None";
        case MitigationAction::RATE_LIMIT: return "Rate Limit";
        case MitigationAction::THROTTLE: return "Throttle";
        case MitigationAction::BLOCK_IP: return "Block IP";
        case MitigationAction::BLOCK_SUBNET: return "Block Subnet";
        case MitigationAction::BLACKHOLE: return "Blackhole";
        case MitigationAction::SYN_COOKIES: return "SYN Cookies";
        case MitigationAction::CONNECTION_RESET: return "Connection Reset";
        case MitigationAction::GEOGRAPHIC_BLOCK: return "Geographic Block";
        case MitigationAction::CHALLENGE: return "Challenge";
        case MitigationAction::ALERT_ONLY: return "Alert Only";
        default: return "Unknown";
    }
}

[[nodiscard]] constexpr const char* AttackPhaseToString(AttackPhase phase) noexcept {
    switch (phase) {
        case AttackPhase::NONE: return "None";
        case AttackPhase::DETECTION: return "Detection";
        case AttackPhase::ESCALATING: return "Escalating";
        case AttackPhase::PEAK: return "Peak";
        case AttackPhase::DECLINING: return "Declining";
        case AttackPhase::RECOVERY: return "Recovery";
        default: return "Unknown";
    }
}

// ============================================================================
// TrafficMetrics METHODS
// ============================================================================

void TrafficMetrics::Reset() noexcept {
    packetsPerSecond.store(0, std::memory_order_relaxed);
    bytesPerSecond.store(0, std::memory_order_relaxed);
    connectionsPerSecond.store(0, std::memory_order_relaxed);
    synPacketsPerSecond.store(0, std::memory_order_relaxed);
    synAckPacketsPerSecond.store(0, std::memory_order_relaxed);
    ackPacketsPerSecond.store(0, std::memory_order_relaxed);
    finPacketsPerSecond.store(0, std::memory_order_relaxed);
    rstPacketsPerSecond.store(0, std::memory_order_relaxed);
    halfOpenConnections.store(0, std::memory_order_relaxed);
    udpPacketsPerSecond.store(0, std::memory_order_relaxed);
    udpBytesPerSecond.store(0, std::memory_order_relaxed);
    icmpPacketsPerSecond.store(0, std::memory_order_relaxed);
    httpRequestsPerSecond.store(0, std::memory_order_relaxed);
    activeHttpConnections.store(0, std::memory_order_relaxed);
    dnsQueriesPerSecond.store(0, std::memory_order_relaxed);
    totalPackets.store(0, std::memory_order_relaxed);
    totalBytes.store(0, std::memory_order_relaxed);
    totalConnections.store(0, std::memory_order_relaxed);
}

// ============================================================================
// DDosProtectionConfig FACTORY METHODS
// ============================================================================

DDosProtectionConfig DDosProtectionConfig::CreateDefault() noexcept {
    return DDosProtectionConfig{};
}

DDosProtectionConfig DDosProtectionConfig::CreateHighSecurity() noexcept {
    DDosProtectionConfig config;
    config.enabled = true;
    config.level = ProtectionLevel::AGGRESSIVE;

    // Enable all detection
    config.enableSynFloodDetection = true;
    config.enableUdpFloodDetection = true;
    config.enableIcmpFloodDetection = true;
    config.enableHttpFloodDetection = true;
    config.enableDnsFloodDetection = true;
    config.enableAmplificationDetection = true;
    config.enableSlowlorisDetection = true;

    // Lower thresholds for aggressive detection
    config.synFloodThreshold = 500;
    config.udpFloodThreshold = 2000;
    config.icmpFloodThreshold = 200;
    config.httpFloodThreshold = 50;
    config.anomalyDeviationThreshold = 2.0;  // 2 sigma

    // Aggressive mitigation
    config.enableRateLimiting = true;
    config.autoMitigate = true;
    config.enableSynCookies = true;
    config.defaultAction = MitigationAction::BLOCK_IP;
    config.blacklistDurationSec = 7200;  // 2 hours

    return config;
}

DDosProtectionConfig DDosProtectionConfig::CreatePerformance() noexcept {
    DDosProtectionConfig config;
    config.enabled = true;
    config.level = ProtectionLevel::STANDARD;

    // Selective detection for lower CPU usage
    config.enableSynFloodDetection = true;
    config.enableUdpFloodDetection = true;
    config.enableIcmpFloodDetection = false;
    config.enableHttpFloodDetection = true;
    config.enableDnsFloodDetection = true;
    config.enableAmplificationDetection = true;
    config.enableSlowlorisDetection = false;

    // Higher thresholds
    config.synFloodThreshold = 2000;
    config.udpFloodThreshold = 10000;
    config.httpFloodThreshold = 200;
    config.anomalyDeviationThreshold = 4.0;  // 4 sigma

    // Lighter tracking
    config.maxTrackedIPs = 50000;
    config.maxHalfOpenConnections = 25000;

    config.logAllPackets = false;
    config.enableBaselineModeling = false;  // Disable to save CPU

    return config;
}

DDosProtectionConfig DDosProtectionConfig::CreateMinimal() noexcept {
    DDosProtectionConfig config;
    config.enabled = true;
    config.level = ProtectionLevel::MINIMAL;

    // Only critical detection
    config.enableSynFloodDetection = true;
    config.enableUdpFloodDetection = false;
    config.enableIcmpFloodDetection = false;
    config.enableHttpFloodDetection = false;
    config.enableDnsFloodDetection = false;
    config.enableAmplificationDetection = false;
    config.enableSlowlorisDetection = false;

    config.synFloodThreshold = 5000;
    config.autoMitigate = false;
    config.defaultAction = MitigationAction::ALERT_ONLY;

    config.maxTrackedIPs = 10000;
    config.maxHalfOpenConnections = 10000;
    config.enableBaselineModeling = false;

    return config;
}

// ============================================================================
// DDosProtectionStatistics METHODS
// ============================================================================

void DDosProtectionStatistics::Reset() noexcept {
    totalPacketsProcessed.store(0, std::memory_order_relaxed);
    totalBytesProcessed.store(0, std::memory_order_relaxed);
    totalConnectionsTracked.store(0, std::memory_order_relaxed);
    attacksDetected.store(0, std::memory_order_relaxed);
    synFloodsDetected.store(0, std::memory_order_relaxed);
    udpFloodsDetected.store(0, std::memory_order_relaxed);
    icmpFloodsDetected.store(0, std::memory_order_relaxed);
    httpFloodsDetected.store(0, std::memory_order_relaxed);
    amplificationAttacks.store(0, std::memory_order_relaxed);
    packetsDropped.store(0, std::memory_order_relaxed);
    bytesDropped.store(0, std::memory_order_relaxed);
    connectionsBlocked.store(0, std::memory_order_relaxed);
    ipsBlacklisted.store(0, std::memory_order_relaxed);
    synCookiesSent.store(0, std::memory_order_relaxed);
    rateLimitHits.store(0, std::memory_order_relaxed);
    activeRateLimits.store(0, std::memory_order_relaxed);
    trackedIPs.store(0, std::memory_order_relaxed);
    halfOpenConnections.store(0, std::memory_order_relaxed);
    alertsGenerated.store(0, std::memory_order_relaxed);
    criticalAlerts.store(0, std::memory_order_relaxed);
    underAttack.store(false, std::memory_order_relaxed);
    currentSeverity.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for DDosProtection.
 */
class DDosProtection::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_attackMutex;
    mutable std::shared_mutex m_ipTrackingMutex;
    mutable std::shared_mutex m_rateLimitMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::mutex m_baselineMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    // Configuration
    DDosProtectionConfig m_config{};

    // Statistics
    DDosProtectionStatistics m_stats{};

    // Traffic metrics (updated by packet processor)
    alignas(64) TrafficMetrics m_currentMetrics{};

    // Baseline (calculated periodically)
    std::optional<TrafficBaseline> m_baseline;

    // Current attack state
    std::optional<AttackInfo> m_currentAttack;
    uint64_t m_nextAttackId{1};

    // IP tracking
    std::unordered_map<std::string, IPTrackingInfo> m_trackedIPs;

    // Rate limiting rules
    std::unordered_map<uint64_t, RateLimitRule> m_rateLimitRules;
    uint64_t m_nextRuleId{1};

    // Half-open connection tracking
    std::deque<HalfOpenConnection> m_halfOpenConnections;

    // Attack history (last 1000 attacks)
    std::deque<AttackInfo> m_attackHistory;
    constexpr static size_t MAX_ATTACK_HISTORY = 1000;

    // Whitelisted IPs
    std::unordered_set<std::string> m_whitelistedIPs;
    std::unordered_set<std::string> m_whitelistedSubnets;

    // Blacklisted IPs
    struct BlacklistEntry {
        std::string ip;
        system_clock::time_point expiresAt;
        MitigationAction action;
    };
    std::unordered_map<std::string, BlacklistEntry> m_blacklistedIPs;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, AttackCallback> m_attackCallbacks;
    std::unordered_map<uint64_t, DDosAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, MitigationCallback> m_mitigationCallbacks;
    std::unordered_map<uint64_t, BlockCallback> m_blockCallbacks;
    std::unordered_map<uint64_t, SeverityCallback> m_severityCallbacks;

    // Worker threads
    std::shared_ptr<ThreadPool> m_threadPool;
    std::vector<std::jthread> m_workerThreads;

    // Timing
    steady_clock::time_point m_metricsWindowStart{steady_clock::now()};
    steady_clock::time_point m_lastBaselineUpdate{steady_clock::now()};

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const DDosProtectionConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("DDosProtection::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("DDosProtection::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Create thread pool
            m_threadPool = std::make_shared<ThreadPool>(4);

            // Initialize whitelists from config
            for (const auto& ip : m_config.whitelistedIPs) {
                m_whitelistedIPs.insert(ip);
            }
            for (const auto& subnet : m_config.whitelistedSubnets) {
                m_whitelistedSubnets.insert(subnet);
            }

            // Reset statistics
            m_stats.Reset();
            m_currentMetrics.Reset();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("DDosProtection::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("DDosProtection::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        if (!m_initialized.load(std::memory_order_acquire)) {
            Logger::Error("DDosProtection: Cannot start - not initialized");
            return false;
        }

        if (m_running.exchange(true, std::memory_order_acquire)) {
            Logger::Warn("DDosProtection: Already running");
            return true;
        }

        try {
            Logger::Info("DDosProtection: Starting protection threads");

            // Start metrics update thread
            m_workerThreads.emplace_back([this](std::stop_token stoken) {
                MetricsUpdateThread(stoken);
            });

            // Start detection thread
            m_workerThreads.emplace_back([this](std::stop_token stoken) {
                DetectionThread(stoken);
            });

            // Start cleanup thread
            m_workerThreads.emplace_back([this](std::stop_token stoken) {
                CleanupThread(stoken);
            });

            Logger::Info("DDosProtection: Protection threads started");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("DDosProtection: Start exception: {}", e.what());
            m_running.store(false, std::memory_order_release);
            return false;
        }
    }

    void Stop() {
        if (!m_running.exchange(false, std::memory_order_acquire)) {
            return;
        }

        Logger::Info("DDosProtection: Stopping protection threads");

        // Stop all worker threads
        m_workerThreads.clear();

        Logger::Info("DDosProtection: Protection threads stopped");
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("DDosProtection::Impl: Shutting down");

        Stop();

        // Clear all data structures
        {
            std::unique_lock ipLock(m_ipTrackingMutex);
            m_trackedIPs.clear();
            m_halfOpenConnections.clear();
        }

        {
            std::unique_lock rateLock(m_rateLimitMutex);
            m_rateLimitRules.clear();
            m_blacklistedIPs.clear();
        }

        {
            std::unique_lock attackLock(m_attackMutex);
            m_attackHistory.clear();
            m_currentAttack.reset();
        }

        {
            std::unique_lock cbLock(m_callbackMutex);
            m_attackCallbacks.clear();
            m_alertCallbacks.clear();
            m_mitigationCallbacks.clear();
            m_blockCallbacks.clear();
            m_severityCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("DDosProtection::Impl: Shutdown complete");
    }

    // ========================================================================
    // WORKER THREADS
    // ========================================================================

    void MetricsUpdateThread(std::stop_token stoken) {
        Logger::Debug("DDosProtection: Metrics update thread started");

        while (!stoken.stop_requested()) {
            try {
                auto now = steady_clock::now();
                auto elapsed = duration_cast<milliseconds>(now - m_metricsWindowStart);

                // Update metrics every second
                if (elapsed >= milliseconds(1000)) {
                    UpdateMetricsWindow();
                    m_metricsWindowStart = now;
                }

                // Calculate baseline every hour
                if (m_config.enableBaselineModeling) {
                    auto baselineAge = duration_cast<hours>(now - m_lastBaselineUpdate);
                    if (baselineAge >= hours(1)) {
                        RecalculateBaselineImpl();
                        m_lastBaselineUpdate = now;
                    }
                }

                std::this_thread::sleep_for(milliseconds(100));

            } catch (const std::exception& e) {
                Logger::Error("DDosProtection: Metrics thread exception: {}", e.what());
            }
        }

        Logger::Debug("DDosProtection: Metrics update thread stopped");
    }

    void DetectionThread(std::stop_token stoken) {
        Logger::Debug("DDosProtection: Detection thread started");

        while (!stoken.stop_requested()) {
            try {
                // Run detection algorithms
                if (m_config.enableSynFloodDetection) {
                    DetectSynFlood();
                }
                if (m_config.enableUdpFloodDetection) {
                    DetectUdpFlood();
                }
                if (m_config.enableIcmpFloodDetection) {
                    DetectIcmpFlood();
                }
                if (m_config.enableHttpFloodDetection) {
                    DetectHttpFlood();
                }
                if (m_config.enableDnsFloodDetection) {
                    DetectDnsFlood();
                }
                if (m_config.enableAmplificationDetection) {
                    DetectAmplificationAttacks();
                }

                // Check for baseline anomalies
                if (m_config.enableBaselineModeling && m_baseline.has_value()) {
                    DetectAnomalies();
                }

                std::this_thread::sleep_for(milliseconds(500));

            } catch (const std::exception& e) {
                Logger::Error("DDosProtection: Detection thread exception: {}", e.what());
            }
        }

        Logger::Debug("DDosProtection: Detection thread stopped");
    }

    void CleanupThread(std::stop_token stoken) {
        Logger::Debug("DDosProtection: Cleanup thread started");

        while (!stoken.stop_requested()) {
            try {
                CleanupExpiredEntries();
                std::this_thread::sleep_for(seconds(60));

            } catch (const std::exception& e) {
                Logger::Error("DDosProtection: Cleanup thread exception: {}", e.what());
            }
        }

        Logger::Debug("DDosProtection: Cleanup thread stopped");
    }

    // ========================================================================
    // METRICS UPDATE
    // ========================================================================

    void UpdateMetricsWindow() {
        // In a real implementation, this would read from network stack
        // For now, we just update the per-second rates from totals

        // Reset per-second counters (they'll be repopulated by packet processing)
        // This is a simplified implementation
    }

    // ========================================================================
    // DETECTION ALGORITHMS
    // ========================================================================

    void DetectSynFlood() {
        uint64_t synRate = m_currentMetrics.synPacketsPerSecond.load(std::memory_order_relaxed);
        uint32_t halfOpen = m_currentMetrics.halfOpenConnections.load(std::memory_order_relaxed);

        uint32_t threshold = m_config.synFloodThreshold > 0 ?
            m_config.synFloodThreshold :
            DDosProtectionConstants::SYN_FLOOD_THRESHOLD_PER_SEC;

        if (synRate > threshold || halfOpen > DDosProtectionConstants::HALF_OPEN_THRESHOLD) {
            Logger::Warn("DDosProtection: SYN flood detected - Rate: {}/s, Half-open: {}",
                synRate, halfOpen);

            AttackInfo attack;
            attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
            attack.type = AttackType::SYN_FLOOD;
            attack.severity = CalculateSeverity(synRate, threshold);
            attack.phase = AttackPhase::DETECTION;
            attack.startTime = system_clock::now();
            attack.lastUpdate = attack.startTime;
            attack.peakPacketsPerSecond = synRate;
            attack.description = std::format("SYN flood: {}/s (threshold: {}/s)", synRate, threshold);

            OnAttackDetected(attack);

            m_stats.synFloodsDetected.fetch_add(1, std::memory_order_relaxed);

            if (m_config.autoMitigate) {
                ApplyMitigationImpl(MitigationAction::SYN_COOKIES, "");
            }
        }
    }

    void DetectUdpFlood() {
        uint64_t udpRate = m_currentMetrics.udpPacketsPerSecond.load(std::memory_order_relaxed);

        uint32_t threshold = m_config.udpFloodThreshold > 0 ?
            m_config.udpFloodThreshold :
            DDosProtectionConstants::UDP_FLOOD_THRESHOLD_PER_SEC;

        if (udpRate > threshold) {
            Logger::Warn("DDosProtection: UDP flood detected - Rate: {}/s", udpRate);

            AttackInfo attack;
            attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
            attack.type = AttackType::UDP_FLOOD;
            attack.severity = CalculateSeverity(udpRate, threshold);
            attack.phase = AttackPhase::DETECTION;
            attack.startTime = system_clock::now();
            attack.lastUpdate = attack.startTime;
            attack.peakPacketsPerSecond = udpRate;
            attack.description = std::format("UDP flood: {}/s (threshold: {}/s)", udpRate, threshold);

            OnAttackDetected(attack);

            m_stats.udpFloodsDetected.fetch_add(1, std::memory_order_relaxed);

            if (m_config.autoMitigate) {
                ApplyMitigationImpl(MitigationAction::RATE_LIMIT, "");
            }
        }
    }

    void DetectIcmpFlood() {
        uint64_t icmpRate = m_currentMetrics.icmpPacketsPerSecond.load(std::memory_order_relaxed);

        uint32_t threshold = m_config.icmpFloodThreshold > 0 ?
            m_config.icmpFloodThreshold :
            DDosProtectionConstants::ICMP_FLOOD_THRESHOLD_PER_SEC;

        if (icmpRate > threshold) {
            Logger::Warn("DDosProtection: ICMP flood detected - Rate: {}/s", icmpRate);

            AttackInfo attack;
            attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
            attack.type = AttackType::ICMP_FLOOD;
            attack.severity = CalculateSeverity(icmpRate, threshold);
            attack.phase = AttackPhase::DETECTION;
            attack.startTime = system_clock::now();
            attack.lastUpdate = attack.startTime;
            attack.peakPacketsPerSecond = icmpRate;
            attack.description = std::format("ICMP flood: {}/s (threshold: {}/s)", icmpRate, threshold);

            OnAttackDetected(attack);

            m_stats.icmpFloodsDetected.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void DetectHttpFlood() {
        uint64_t httpRate = m_currentMetrics.httpRequestsPerSecond.load(std::memory_order_relaxed);

        uint32_t threshold = m_config.httpFloodThreshold > 0 ?
            m_config.httpFloodThreshold :
            DDosProtectionConstants::HTTP_REQUESTS_PER_SEC;

        if (httpRate > threshold) {
            Logger::Warn("DDosProtection: HTTP flood detected - Rate: {}/s", httpRate);

            AttackInfo attack;
            attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
            attack.type = AttackType::HTTP_GET_FLOOD;
            attack.severity = CalculateSeverity(httpRate, threshold);
            attack.phase = AttackPhase::DETECTION;
            attack.startTime = system_clock::now();
            attack.lastUpdate = attack.startTime;
            attack.peakPacketsPerSecond = httpRate;
            attack.description = std::format("HTTP flood: {}/s (threshold: {}/s)", httpRate, threshold);

            OnAttackDetected(attack);

            m_stats.httpFloodsDetected.fetch_add(1, std::memory_order_relaxed);

            if (m_config.autoMitigate) {
                ApplyMitigationImpl(MitigationAction::CHALLENGE, "");
            }
        }
    }

    void DetectDnsFlood() {
        uint64_t dnsRate = m_currentMetrics.dnsQueriesPerSecond.load(std::memory_order_relaxed);

        // DNS flood threshold (default: 1000/s)
        uint32_t threshold = 1000;

        if (dnsRate > threshold) {
            Logger::Warn("DDosProtection: DNS flood detected - Rate: {}/s", dnsRate);

            AttackInfo attack;
            attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
            attack.type = AttackType::DNS_QUERY_FLOOD;
            attack.severity = CalculateSeverity(dnsRate, threshold);
            attack.phase = AttackPhase::DETECTION;
            attack.startTime = system_clock::now();
            attack.lastUpdate = attack.startTime;
            attack.peakPacketsPerSecond = dnsRate;
            attack.description = std::format("DNS flood: {}/s (threshold: {}/s)", dnsRate, threshold);

            OnAttackDetected(attack);
        }
    }

    void DetectAmplificationAttacks() {
        // Check for amplification patterns (many responses from few sources)
        // This is a simplified heuristic

        uint64_t udpRate = m_currentMetrics.udpPacketsPerSecond.load(std::memory_order_relaxed);
        uint64_t udpBytes = m_currentMetrics.udpBytesPerSecond.load(std::memory_order_relaxed);

        // If UDP traffic has high byte-to-packet ratio, possible amplification
        if (udpRate > 0) {
            double avgPacketSize = static_cast<double>(udpBytes) / udpRate;

            // Amplification attacks often have large packets (>1000 bytes)
            if (avgPacketSize > 1000) {
                Logger::Warn("DDosProtection: Possible amplification attack - Avg packet: {} bytes",
                    avgPacketSize);

                AttackInfo attack;
                attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
                attack.type = AttackType::REFLECTION;
                attack.severity = AttackSeverity::HIGH;
                attack.phase = AttackPhase::DETECTION;
                attack.startTime = system_clock::now();
                attack.lastUpdate = attack.startTime;
                attack.peakBytesPerSecond = udpBytes;
                attack.description = std::format("Amplification attack: avg pkt {} bytes",
                    static_cast<uint64_t>(avgPacketSize));

                OnAttackDetected(attack);

                m_stats.amplificationAttacks.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void DetectAnomalies() {
        if (!m_baseline.has_value()) return;

        const auto& baseline = m_baseline.value();
        uint64_t currentPPS = m_currentMetrics.packetsPerSecond.load(std::memory_order_relaxed);

        // Check if current rate deviates significantly from baseline
        double deviation = (currentPPS - baseline.avgPacketsPerSecond) /
                          (baseline.stdDevPacketsPerSecond + 1.0);

        if (std::abs(deviation) > m_config.anomalyDeviationThreshold) {
            Logger::Warn("DDosProtection: Traffic anomaly detected - Deviation: {:.2f} sigma", deviation);

            AttackInfo attack;
            attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
            attack.type = AttackType::UNKNOWN;
            attack.severity = AttackSeverity::MEDIUM;
            attack.phase = AttackPhase::DETECTION;
            attack.startTime = system_clock::now();
            attack.lastUpdate = attack.startTime;
            attack.peakPacketsPerSecond = currentPPS;
            attack.description = std::format("Traffic anomaly: {:.2f}σ from baseline", deviation);

            OnAttackDetected(attack);
        }
    }

    // ========================================================================
    // SEVERITY CALCULATION
    // ========================================================================

    [[nodiscard]] AttackSeverity CalculateSeverity(uint64_t currentRate, uint32_t threshold) const noexcept {
        if (threshold == 0) return AttackSeverity::MEDIUM;

        double ratio = static_cast<double>(currentRate) / threshold;

        if (ratio < 1.5) return AttackSeverity::LOW;
        if (ratio < 3.0) return AttackSeverity::MEDIUM;
        if (ratio < 10.0) return AttackSeverity::HIGH;
        return AttackSeverity::CRITICAL;
    }

    // ========================================================================
    // ATTACK MANAGEMENT
    // ========================================================================

    void OnAttackDetected(const AttackInfo& attack) {
        std::unique_lock lock(m_attackMutex);

        // Update or create current attack
        if (!m_currentAttack.has_value()) {
            m_currentAttack = attack;
            m_stats.attacksDetected.fetch_add(1, std::memory_order_relaxed);
            m_stats.underAttack.store(true, std::memory_order_relaxed);

            Logger::Warn("DDosProtection: Attack {} started - Type: {}, Severity: {}",
                attack.attackId, AttackTypeToString(attack.type),
                AttackSeverityToString(attack.severity));

        } else {
            // Update existing attack
            m_currentAttack->lastUpdate = system_clock::now();
            m_currentAttack->peakPacketsPerSecond = std::max(
                m_currentAttack->peakPacketsPerSecond, attack.peakPacketsPerSecond);

            // Update phase
            if (attack.peakPacketsPerSecond > m_currentAttack->peakPacketsPerSecond * 1.5) {
                m_currentAttack->phase = AttackPhase::ESCALATING;
            }
        }

        // Store severity
        m_stats.currentSeverity.store(static_cast<uint8_t>(attack.severity),
            std::memory_order_relaxed);

        // Generate alert
        GenerateAlert(attack);

        // Invoke callbacks
        InvokeAttackCallbacks(attack);
    }

    void OnAttackEnded() {
        std::unique_lock lock(m_attackMutex);

        if (m_currentAttack.has_value()) {
            auto& attack = m_currentAttack.value();
            attack.endTime = system_clock::now();
            attack.phase = AttackPhase::RECOVERY;
            attack.duration = duration_cast<milliseconds>(attack.endTime - attack.startTime);

            Logger::Info("DDosProtection: Attack {} ended - Duration: {} ms",
                attack.attackId, attack.duration.count());

            // Add to history
            m_attackHistory.push_back(attack);
            if (m_attackHistory.size() > MAX_ATTACK_HISTORY) {
                m_attackHistory.pop_front();
            }

            m_currentAttack.reset();
            m_stats.underAttack.store(false, std::memory_order_relaxed);
            m_stats.currentSeverity.store(0, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // MITIGATION
    // ========================================================================

    [[nodiscard]] MitigationResult ApplyMitigationImpl(
        MitigationAction action,
        const std::string& targetIP
    ) {
        MitigationResult result;
        result.mitigationId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
        result.action = action;
        result.targetIP = targetIP;
        result.appliedAt = system_clock::now();

        try {
            Logger::Info("DDosProtection: Applying mitigation - Action: {}, Target: {}",
                MitigationActionToString(action), targetIP.empty() ? "global" : targetIP);

            switch (action) {
                case MitigationAction::RATE_LIMIT:
                    result.success = ApplyRateLimitMitigation(targetIP);
                    break;

                case MitigationAction::BLOCK_IP:
                    result.success = BlockIPImpl(targetIP, m_config.blacklistDurationSec);
                    break;

                case MitigationAction::SYN_COOKIES:
                    result.success = EnableSynCookies();
                    break;

                case MitigationAction::CONNECTION_RESET:
                    result.success = ResetConnections(targetIP);
                    break;

                case MitigationAction::ALERT_ONLY:
                    result.success = true;
                    break;

                default:
                    result.success = false;
                    result.errorMessage = "Mitigation action not implemented";
                    break;
            }

            if (result.success) {
                Logger::Info("DDosProtection: Mitigation applied successfully");
                InvokeMitigationCallbacks(result);
            } else {
                Logger::Error("DDosProtection: Mitigation failed: {}", result.errorMessage);
            }

        } catch (const std::exception& e) {
            result.success = false;
            result.errorMessage = e.what();
            Logger::Error("DDosProtection: Mitigation exception: {}", e.what());
        }

        return result;
    }

    [[nodiscard]] bool ApplyRateLimitMitigation(const std::string& targetIP) {
        RateLimitRule rule;
        rule.ruleId = m_nextRuleId.fetch_add(1, std::memory_order_relaxed);
        rule.name = "Auto-mitigation rate limit";
        rule.ipAddress = targetIP;
        rule.packetsPerSecond = m_config.defaultRateLimitPPS / 10;  // 10% of normal
        rule.exceedAction = MitigationAction::BLOCK_IP;
        rule.blockDurationSec = 300;  // 5 minutes
        rule.createdAt = system_clock::now();
        rule.expiresAt = rule.createdAt + seconds(m_config.blacklistDurationSec);
        rule.isPermanent = false;

        std::unique_lock lock(m_rateLimitMutex);
        m_rateLimitRules[rule.ruleId] = rule;
        m_stats.activeRateLimits.fetch_add(1, std::memory_order_relaxed);

        return true;
    }

    [[nodiscard]] bool BlockIPImpl(const std::string& ip, uint32_t durationSec) {
        if (ip.empty()) return false;

        // Check whitelist
        if (IsWhitelistedImpl(ip)) {
            Logger::Warn("DDosProtection: Cannot block whitelisted IP: {}", ip);
            return false;
        }

        std::unique_lock lock(m_rateLimitMutex);

        BlacklistEntry entry;
        entry.ip = ip;
        entry.expiresAt = system_clock::now() + seconds(durationSec);
        entry.action = MitigationAction::BLOCK_IP;

        m_blacklistedIPs[ip] = entry;
        m_stats.ipsBlacklisted.fetch_add(1, std::memory_order_relaxed);

        Logger::Info("DDosProtection: IP {} blocked for {} seconds", ip, durationSec);

        InvokeBlockCallbacks(ip, MitigationAction::BLOCK_IP, durationSec);

        // In real implementation, would update Windows Filtering Platform rules
        return true;
    }

    [[nodiscard]] bool EnableSynCookies() {
        Logger::Info("DDosProtection: Enabling SYN cookies");
        m_stats.synCookiesSent.fetch_add(1, std::memory_order_relaxed);

        // In real implementation, would configure TCP stack
        return true;
    }

    [[nodiscard]] bool ResetConnections(const std::string& targetIP) {
        Logger::Info("DDosProtection: Resetting connections for {}",
            targetIP.empty() ? "all" : targetIP);

        // In real implementation, would send RST packets
        return true;
    }

    // ========================================================================
    // IP TRACKING
    // ========================================================================

    [[nodiscard]] std::optional<IPTrackingInfo> GetIPInfoImpl(const std::string& ip) const {
        std::shared_lock lock(m_ipTrackingMutex);

        auto it = m_trackedIPs.find(ip);
        if (it != m_trackedIPs.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void UpdateIPTracking(const std::string& ip, uint64_t bytes, bool isSyn) {
        std::unique_lock lock(m_ipTrackingMutex);

        // Check tracking limit
        if (m_trackedIPs.size() >= m_config.maxTrackedIPs &&
            m_trackedIPs.find(ip) == m_trackedIPs.end()) {
            return;  // Limit reached
        }

        auto& info = m_trackedIPs[ip];
        info.ipAddress = ip;
        info.packetsTotal.fetch_add(1, std::memory_order_relaxed);
        info.bytesTotal.fetch_add(bytes, std::memory_order_relaxed);
        info.packetsInWindow.fetch_add(1, std::memory_order_relaxed);
        info.lastSeen = system_clock::now();

        if (isSyn) {
            info.synPackets.fetch_add(1, std::memory_order_relaxed);
        }

        if (info.firstSeen == system_clock::time_point{}) {
            info.firstSeen = info.lastSeen;
        }

        m_stats.trackedIPs.store(m_trackedIPs.size(), std::memory_order_relaxed);
    }

    // ========================================================================
    // WHITELIST
    // ========================================================================

    [[nodiscard]] bool IsWhitelistedImpl(const std::string& ip) const {
        std::shared_lock lock(m_ipTrackingMutex);
        return m_whitelistedIPs.find(ip) != m_whitelistedIPs.end();
    }

    bool AddToWhitelistImpl(const std::string& ip) {
        std::unique_lock lock(m_ipTrackingMutex);
        m_whitelistedIPs.insert(ip);
        Logger::Info("DDosProtection: IP {} added to whitelist", ip);
        return true;
    }

    bool RemoveFromWhitelistImpl(const std::string& ip) {
        std::unique_lock lock(m_ipTrackingMutex);
        auto removed = m_whitelistedIPs.erase(ip) > 0;
        if (removed) {
            Logger::Info("DDosProtection: IP {} removed from whitelist", ip);
        }
        return removed;
    }

    // ========================================================================
    // BASELINE CALCULATION
    // ========================================================================

    void RecalculateBaselineImpl() {
        std::unique_lock lock(m_baselineMutex);

        try {
            Logger::Debug("DDosProtection: Recalculating traffic baseline");

            TrafficBaseline baseline;

            // In real implementation, would analyze historical data
            // For now, use current metrics as baseline
            baseline.avgPacketsPerSecond = m_currentMetrics.packetsPerSecond.load(std::memory_order_relaxed);
            baseline.avgBytesPerSecond = m_currentMetrics.bytesPerSecond.load(std::memory_order_relaxed);
            baseline.avgConnectionsPerSecond = m_currentMetrics.connectionsPerSecond.load(std::memory_order_relaxed);
            baseline.avgHalfOpenConnections = m_currentMetrics.halfOpenConnections.load(std::memory_order_relaxed);
            baseline.avgSynRate = m_currentMetrics.synPacketsPerSecond.load(std::memory_order_relaxed);
            baseline.avgUdpRate = m_currentMetrics.udpPacketsPerSecond.load(std::memory_order_relaxed);
            baseline.avgIcmpRate = m_currentMetrics.icmpPacketsPerSecond.load(std::memory_order_relaxed);
            baseline.avgHttpRate = m_currentMetrics.httpRequestsPerSecond.load(std::memory_order_relaxed);

            // Calculate standard deviations (simplified - would need historical samples)
            baseline.stdDevPacketsPerSecond = baseline.avgPacketsPerSecond * 0.2;
            baseline.stdDevBytesPerSecond = baseline.avgBytesPerSecond * 0.2;
            baseline.stdDevConnectionsPerSecond = baseline.avgConnectionsPerSecond * 0.2;

            baseline.calculatedAt = system_clock::now();
            baseline.samplePeriod = m_config.baselineSamplePeriod;
            baseline.sampleCount = 1;
            baseline.isValid = true;

            m_baseline = baseline;

            Logger::Info("DDosProtection: Baseline updated - PPS: {:.0f}, BPS: {:.0f}",
                baseline.avgPacketsPerSecond, baseline.avgBytesPerSecond);

        } catch (const std::exception& e) {
            Logger::Error("DDosProtection: Baseline calculation exception: {}", e.what());
        }
    }

    // ========================================================================
    // CLEANUP
    // ========================================================================

    void CleanupExpiredEntries() {
        auto now = system_clock::now();

        // Cleanup blacklisted IPs
        {
            std::unique_lock lock(m_rateLimitMutex);

            for (auto it = m_blacklistedIPs.begin(); it != m_blacklistedIPs.end();) {
                if (it->second.expiresAt < now) {
                    Logger::Debug("DDosProtection: Unblocking expired IP: {}", it->first);
                    it = m_blacklistedIPs.erase(it);
                } else {
                    ++it;
                }
            }

            // Cleanup expired rate limit rules
            for (auto it = m_rateLimitRules.begin(); it != m_rateLimitRules.end();) {
                if (!it->second.isPermanent && it->second.expiresAt < now) {
                    Logger::Debug("DDosProtection: Removing expired rate limit rule {}", it->first);
                    it = m_rateLimitRules.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Cleanup old IP tracking entries
        {
            std::unique_lock lock(m_ipTrackingMutex);

            auto timeout = now - seconds(DDosProtectionConstants::IP_TRACKING_TIMEOUT_SEC);
            for (auto it = m_trackedIPs.begin(); it != m_trackedIPs.end();) {
                if (it->second.lastSeen < timeout) {
                    it = m_trackedIPs.erase(it);
                } else {
                    ++it;
                }
            }

            m_stats.trackedIPs.store(m_trackedIPs.size(), std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // ALERTS
    // ========================================================================

    void GenerateAlert(const AttackInfo& attack) {
        DDosAlert alert;
        alert.alertId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
        alert.timestamp = system_clock::now();
        alert.attackId = attack.attackId;
        alert.attackType = attack.type;
        alert.severity = attack.severity;
        alert.phase = attack.phase;
        alert.title = std::format("DDoS Attack Detected: {}", AttackTypeToString(attack.type));
        alert.description = attack.description;
        alert.currentPacketsPerSecond = attack.peakPacketsPerSecond;
        alert.currentBytesPerSecond = attack.peakBytesPerSecond;
        alert.recommendedAction = m_config.defaultAction;

        m_stats.alertsGenerated.fetch_add(1, std::memory_order_relaxed);
        if (attack.severity == AttackSeverity::CRITICAL) {
            m_stats.criticalAlerts.fetch_add(1, std::memory_order_relaxed);
        }

        InvokeAlertCallbacks(alert);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeAttackCallbacks(const AttackInfo& attack) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_attackCallbacks) {
            try {
                callback(attack);
            } catch (const std::exception& e) {
                Logger::Error("DDosProtection: Attack callback exception: {}", e.what());
            }
        }
    }

    void InvokeAlertCallbacks(const DDosAlert& alert) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_alertCallbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                Logger::Error("DDosProtection: Alert callback exception: {}", e.what());
            }
        }
    }

    void InvokeMitigationCallbacks(const MitigationResult& result) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_mitigationCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("DDosProtection: Mitigation callback exception: {}", e.what());
            }
        }
    }

    void InvokeBlockCallbacks(const std::string& ip, MitigationAction action, uint32_t durationSec) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_blockCallbacks) {
            try {
                callback(ip, action, durationSec);
            } catch (const std::exception& e) {
                Logger::Error("DDosProtection: Block callback exception: {}", e.what());
            }
        }
    }

    // ========================================================================
    // ATTACK HISTORY
    // ========================================================================

    [[nodiscard]] std::vector<AttackInfo> GetAttackHistoryImpl(size_t maxCount) const {
        std::shared_lock lock(m_attackMutex);

        std::vector<AttackInfo> result;
        result.reserve(std::min(maxCount, m_attackHistory.size()));

        auto it = m_attackHistory.rbegin();
        for (size_t i = 0; i < maxCount && it != m_attackHistory.rend(); ++i, ++it) {
            result.push_back(*it);
        }

        return result;
    }

    [[nodiscard]] std::vector<AttackInfo> GetAttacksInRangeImpl(
        system_clock::time_point start,
        system_clock::time_point end
    ) const {
        std::shared_lock lock(m_attackMutex);

        std::vector<AttackInfo> result;

        for (const auto& attack : m_attackHistory) {
            if (attack.startTime >= start && attack.startTime <= end) {
                result.push_back(attack);
            }
        }

        return result;
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

DDosProtection& DDosProtection::Instance() {
    static DDosProtection instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

DDosProtection::DDosProtection()
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("DDosProtection: Constructor called");
}

DDosProtection::~DDosProtection() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("DDosProtection: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool DDosProtection::Initialize(const DDosProtectionConfig& config) {
    if (!m_impl) {
        Logger::Critical("DDosProtection: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

bool DDosProtection::Start() {
    if (!m_impl) {
        Logger::Error("DDosProtection: Implementation is null");
        return false;
    }

    return m_impl->Start();
}

void DDosProtection::Stop() {
    if (m_impl) {
        m_impl->Stop();
    }
}

void DDosProtection::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] bool DDosProtection::IsRunning() const noexcept {
    return m_impl && m_impl->m_running.load(std::memory_order_acquire);
}

// ============================================================================
// ATTACK DETECTION
// ============================================================================

[[nodiscard]] bool DDosProtection::IsUnderAttack() {
    return m_impl && m_impl->m_stats.underAttack.load(std::memory_order_acquire);
}

[[nodiscard]] std::optional<AttackInfo> DDosProtection::GetCurrentAttack() const {
    if (!m_impl) return std::nullopt;

    std::shared_lock lock(m_impl->m_attackMutex);
    return m_impl->m_currentAttack;
}

[[nodiscard]] AttackSeverity DDosProtection::GetCurrentSeverity() const noexcept {
    if (!m_impl) return AttackSeverity::NONE;

    uint8_t severity = m_impl->m_stats.currentSeverity.load(std::memory_order_acquire);
    return static_cast<AttackSeverity>(severity);
}

[[nodiscard]] bool DDosProtection::DetectAttack(AttackType type) const {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_attackMutex);

    if (m_impl->m_currentAttack.has_value()) {
        return m_impl->m_currentAttack->type == type;
    }

    return false;
}

// ============================================================================
// MITIGATION
// ============================================================================

void DDosProtection::Mitigate() {
    if (!m_impl) return;

    if (m_impl->m_currentAttack.has_value()) {
        m_impl->ApplyMitigationImpl(m_impl->m_config.defaultAction, "");
    }
}

[[nodiscard]] MitigationResult DDosProtection::ApplyMitigation(
    MitigationAction action,
    const std::string& targetIP
) {
    if (!m_impl) {
        MitigationResult result;
        result.success = false;
        result.errorMessage = "Not initialized";
        return result;
    }

    return m_impl->ApplyMitigationImpl(action, targetIP);
}

bool DDosProtection::BlockIP(const std::string& ip, uint32_t durationSec) {
    if (!m_impl || ip.empty()) return false;

    uint32_t duration = (durationSec == 0) ?
        m_impl->m_config.blacklistDurationSec : durationSec;

    return m_impl->BlockIPImpl(ip, duration);
}

bool DDosProtection::BlockSubnet(const std::string& subnet, uint32_t durationSec) {
    if (!m_impl || subnet.empty()) return false;

    // In real implementation, would parse subnet and block all IPs
    Logger::Info("DDosProtection: Blocking subnet {} for {} seconds", subnet, durationSec);
    return true;
}

bool DDosProtection::UnblockIP(const std::string& ip) {
    if (!m_impl || ip.empty()) return false;

    std::unique_lock lock(m_impl->m_rateLimitMutex);

    auto removed = m_impl->m_blacklistedIPs.erase(ip) > 0;
    if (removed) {
        Logger::Info("DDosProtection: IP {} unblocked", ip);
    }

    return removed;
}

void DDosProtection::ClearAllMitigations() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_rateLimitMutex);

    m_impl->m_blacklistedIPs.clear();
    m_impl->m_rateLimitRules.clear();

    Logger::Info("DDosProtection: All mitigations cleared");
}

// ============================================================================
// RATE LIMITING
// ============================================================================

[[nodiscard]] uint64_t DDosProtection::AddRateLimitRule(const RateLimitRule& rule) {
    if (!m_impl) return 0;

    std::unique_lock lock(m_impl->m_rateLimitMutex);

    uint64_t ruleId = m_impl->m_nextRuleId.fetch_add(1, std::memory_order_relaxed);

    RateLimitRule newRule = rule;
    newRule.ruleId = ruleId;
    newRule.createdAt = system_clock::now();

    m_impl->m_rateLimitRules[ruleId] = newRule;
    m_impl->m_stats.activeRateLimits.fetch_add(1, std::memory_order_relaxed);

    Logger::Info("DDosProtection: Rate limit rule {} added", ruleId);

    return ruleId;
}

bool DDosProtection::RemoveRateLimitRule(uint64_t ruleId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_rateLimitMutex);

    auto removed = m_impl->m_rateLimitRules.erase(ruleId) > 0;
    if (removed) {
        m_impl->m_stats.activeRateLimits.fetch_sub(1, std::memory_order_relaxed);
        Logger::Info("DDosProtection: Rate limit rule {} removed", ruleId);
    }

    return removed;
}

bool DDosProtection::RateLimitIP(const std::string& ip, uint32_t packetsPerSecond) {
    if (!m_impl || ip.empty()) return false;

    RateLimitRule rule;
    rule.name = std::format("Rate limit for {}", ip);
    rule.ipAddress = ip;
    rule.packetsPerSecond = packetsPerSecond;
    rule.exceedAction = MitigationAction::THROTTLE;
    rule.blockDurationSec = 60;

    AddRateLimitRule(rule);
    return true;
}

[[nodiscard]] bool DDosProtection::IsRateLimited(const std::string& ip) const {
    if (!m_impl || ip.empty()) return false;

    std::shared_lock lock(m_impl->m_rateLimitMutex);

    for (const auto& [id, rule] : m_impl->m_rateLimitRules) {
        if (rule.enabled && (rule.ipAddress == ip || rule.ipAddress.empty())) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// TRAFFIC ANALYSIS
// ============================================================================

[[nodiscard]] TrafficMetrics DDosProtection::GetCurrentMetrics() const {
    if (!m_impl) return TrafficMetrics{};
    return m_impl->m_currentMetrics;
}

[[nodiscard]] std::optional<TrafficBaseline> DDosProtection::GetBaseline() const {
    if (!m_impl) return std::nullopt;

    std::unique_lock lock(m_impl->m_baselineMutex);
    return m_impl->m_baseline;
}

void DDosProtection::RecalculateBaseline() {
    if (m_impl) {
        m_impl->RecalculateBaselineImpl();
    }
}

[[nodiscard]] std::optional<IPTrackingInfo> DDosProtection::GetIPInfo(const std::string& ip) const {
    if (!m_impl) return std::nullopt;
    return m_impl->GetIPInfoImpl(ip);
}

// ============================================================================
// WHITELIST MANAGEMENT
// ============================================================================

bool DDosProtection::AddToWhitelist(const std::string& ip) {
    if (!m_impl) return false;
    return m_impl->AddToWhitelistImpl(ip);
}

bool DDosProtection::RemoveFromWhitelist(const std::string& ip) {
    if (!m_impl) return false;
    return m_impl->RemoveFromWhitelistImpl(ip);
}

[[nodiscard]] bool DDosProtection::IsWhitelisted(const std::string& ip) const {
    if (!m_impl) return false;
    return m_impl->IsWhitelistedImpl(ip);
}

// ============================================================================
// ATTACK HISTORY
// ============================================================================

[[nodiscard]] std::vector<AttackInfo> DDosProtection::GetAttackHistory(size_t maxCount) const {
    if (!m_impl) return {};
    return m_impl->GetAttackHistoryImpl(maxCount);
}

[[nodiscard]] std::vector<AttackInfo> DDosProtection::GetAttacksInRange(
    system_clock::time_point start,
    system_clock::time_point end
) const {
    if (!m_impl) return {};
    return m_impl->GetAttacksInRangeImpl(start, end);
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

[[nodiscard]] uint64_t DDosProtection::RegisterAttackCallback(AttackCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_attackCallbacks[id] = std::move(callback);

    Logger::Debug("DDosProtection: Registered attack callback {}", id);
    return id;
}

[[nodiscard]] uint64_t DDosProtection::RegisterAlertCallback(DDosAlertCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_alertCallbacks[id] = std::move(callback);

    Logger::Debug("DDosProtection: Registered alert callback {}", id);
    return id;
}

[[nodiscard]] uint64_t DDosProtection::RegisterMitigationCallback(MitigationCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_mitigationCallbacks[id] = std::move(callback);

    Logger::Debug("DDosProtection: Registered mitigation callback {}", id);
    return id;
}

[[nodiscard]] uint64_t DDosProtection::RegisterBlockCallback(BlockCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_blockCallbacks[id] = std::move(callback);

    Logger::Debug("DDosProtection: Registered block callback {}", id);
    return id;
}

[[nodiscard]] uint64_t DDosProtection::RegisterSeverityCallback(SeverityCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_severityCallbacks[id] = std::move(callback);

    Logger::Debug("DDosProtection: Registered severity callback {}", id);
    return id;
}

bool DDosProtection::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);

    bool removed = false;
    removed |= m_impl->m_attackCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_alertCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_mitigationCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_blockCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_severityCallbacks.erase(callbackId) > 0;

    return removed;
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] const DDosProtectionStatistics& DDosProtection::GetStatistics() const noexcept {
    static DDosProtectionStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void DDosProtection::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("DDosProtection: Statistics reset");
    }
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

[[nodiscard]] bool DDosProtection::PerformDiagnostics() const {
    if (!m_impl) return false;

    try {
        Logger::Info("DDosProtection: Running diagnostics");

        // Check initialization
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            Logger::Error("DDosProtection: Not initialized");
            return false;
        }

        // Check configuration
        if (!m_impl->m_config.enabled) {
            Logger::Warn("DDosProtection: Protection is disabled");
        }

        // Check running state
        if (!m_impl->m_running.load(std::memory_order_acquire)) {
            Logger::Warn("DDosProtection: Not running");
        }

        // Check tracking limits
        {
            std::shared_lock lock(m_impl->m_ipTrackingMutex);
            size_t trackedCount = m_impl->m_trackedIPs.size();
            Logger::Info("DDosProtection: Tracking {} IPs (limit: {})",
                trackedCount, m_impl->m_config.maxTrackedIPs);
        }

        // Check rate limit rules
        {
            std::shared_lock lock(m_impl->m_rateLimitMutex);
            Logger::Info("DDosProtection: {} active rate limit rules",
                m_impl->m_rateLimitRules.size());
            Logger::Info("DDosProtection: {} blacklisted IPs",
                m_impl->m_blacklistedIPs.size());
        }

        Logger::Info("DDosProtection: Diagnostics passed");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("DDosProtection: Diagnostics exception: {}", e.what());
        return false;
    }
}

bool DDosProtection::ExportDiagnostics(const std::wstring& outputPath) const {
    if (!m_impl) return false;

    try {
        std::ofstream file(outputPath);
        if (!file) {
            Logger::Error("DDosProtection: Cannot create diagnostics file");
            return false;
        }

        file << "=== ShadowStrike DDoS Protection Diagnostics ===\n\n";

        // Configuration
        file << "CONFIGURATION:\n";
        file << "  Enabled: " << (m_impl->m_config.enabled ? "Yes" : "No") << "\n";
        file << "  Protection Level: " << static_cast<int>(m_impl->m_config.level) << "\n";
        file << "  Auto-Mitigation: " << (m_impl->m_config.autoMitigate ? "Yes" : "No") << "\n\n";

        // Statistics
        const auto& stats = m_impl->m_stats;
        file << "STATISTICS:\n";
        file << "  Total Packets: " << stats.totalPacketsProcessed.load() << "\n";
        file << "  Total Bytes: " << stats.totalBytesProcessed.load() << "\n";
        file << "  Attacks Detected: " << stats.attacksDetected.load() << "\n";
        file << "  Packets Dropped: " << stats.packetsDropped.load() << "\n";
        file << "  IPs Blacklisted: " << stats.ipsBlacklisted.load() << "\n";
        file << "  Under Attack: " << (stats.underAttack.load() ? "YES" : "No") << "\n\n";

        // Current metrics
        file << "CURRENT METRICS:\n";
        file << "  PPS: " << m_impl->m_currentMetrics.packetsPerSecond.load() << "\n";
        file << "  BPS: " << m_impl->m_currentMetrics.bytesPerSecond.load() << "\n";
        file << "  Half-Open: " << m_impl->m_currentMetrics.halfOpenConnections.load() << "\n\n";

        file.close();
        Logger::Info("DDosProtection: Diagnostics exported to {}",
            StringUtils::WideToUtf8(outputPath));

        return true;

    } catch (const std::exception& e) {
        Logger::Error("DDosProtection: Export diagnostics exception: {}", e.what());
        return false;
    }
}

bool DDosProtection::ExportAttackReport(const std::wstring& outputPath, uint64_t attackId) const {
    if (!m_impl) return false;

    try {
        std::shared_lock lock(m_impl->m_attackMutex);

        // Find attack in history
        const AttackInfo* attackPtr = nullptr;

        if (m_impl->m_currentAttack.has_value() &&
            m_impl->m_currentAttack->attackId == attackId) {
            attackPtr = &m_impl->m_currentAttack.value();
        } else {
            for (const auto& attack : m_impl->m_attackHistory) {
                if (attack.attackId == attackId) {
                    attackPtr = &attack;
                    break;
                }
            }
        }

        if (!attackPtr) {
            Logger::Error("DDosProtection: Attack {} not found", attackId);
            return false;
        }

        const auto& attack = *attackPtr;

        std::ofstream file(outputPath);
        if (!file) {
            Logger::Error("DDosProtection: Cannot create attack report file");
            return false;
        }

        file << "=== ShadowStrike DDoS Attack Report ===\n\n";
        file << "Attack ID: " << attack.attackId << "\n";
        file << "Type: " << AttackTypeToString(attack.type) << "\n";
        file << "Severity: " << AttackSeverityToString(attack.severity) << "\n";
        file << "Phase: " << AttackPhaseToString(attack.phase) << "\n";
        file << "Description: " << attack.description << "\n\n";

        file << "TIMELINE:\n";
        file << "  Start: [timestamp]\n";
        file << "  Duration: " << attack.duration.count() << " ms\n\n";

        file << "TRAFFIC METRICS:\n";
        file << "  Peak PPS: " << attack.peakPacketsPerSecond << "\n";
        file << "  Peak BPS: " << attack.peakBytesPerSecond << "\n";
        file << "  Total Packets: " << attack.totalPackets << "\n";
        file << "  Total Bytes: " << attack.totalBytes << "\n\n";

        file << "SOURCE ANALYSIS:\n";
        file << "  Unique IPs: " << attack.uniqueSourceIPs << "\n";
        file << "  Distributed: " << (attack.isDistributed ? "Yes" : "No") << "\n\n";

        file << "MITIGATION:\n";
        file << "  Status: " << (attack.isMitigated ? "Mitigated" : "Not Mitigated") << "\n";
        file << "  Effectiveness: " << attack.mitigationEffectiveness << "%\n\n";

        file.close();
        Logger::Info("DDosProtection: Attack report exported");

        return true;

    } catch (const std::exception& e) {
        Logger::Error("DDosProtection: Export attack report exception: {}", e.what());
        return false;
    }
}

} // namespace Network
} // namespace Core
} // namespace ShadowStrike
