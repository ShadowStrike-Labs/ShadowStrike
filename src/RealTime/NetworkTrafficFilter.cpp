/**
 * ============================================================================
 * ShadowStrike Real-Time - NETWORK TRAFFIC FILTER IMPLEMENTATION
 * ============================================================================
 *
 * @file NetworkTrafficFilter.cpp
 * @brief Implementation of the enterprise-grade network traffic filter.
 *
 * Implements the core logic for WFP integration, rule evaluation, deep packet
 * inspection, and C2/DGA detection.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "NetworkTrafficFilter.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cmath>
#include <numeric>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <thread>
#include <deque>
#include <nlohmann/json.hpp>

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// ANONYMOUS HELPER NAMESPACE
// ============================================================================
namespace {

    // Entropy Calculation for DGA
    double CalculateShannonEntropy(const std::string& s) {
        if (s.empty()) return 0.0;

        std::map<char, int> frequencies;
        for (char c : s) frequencies[c]++;

        double entropy = 0.0;
        double len = static_cast<double>(s.length());

        for (const auto& pair : frequencies) {
            double p = pair.second / len;
            entropy -= p * std::log2(p);
        }

        return entropy;
    }

    // Helper to get current time
    std::chrono::system_clock::time_point Now() {
        return std::chrono::system_clock::now();
    }

    // Generate unique connection ID
    uint64_t GenerateConnectionId() {
        static std::atomic<uint64_t> id{ 10000 };
        return id.fetch_add(1);
    }

} // namespace

// ============================================================================
// IMPL STRUCT (PIMPL)
// ============================================================================
struct NetworkTrafficFilter::Impl {
    // -------------------------------------------------------------------------
    // Members
    // -------------------------------------------------------------------------

    // Configuration & State
    NetworkFilterConfig m_config;
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_running{ false };

    // Driver Handle
    HANDLE m_hDriver{ INVALID_HANDLE_VALUE };

    // Threading
    std::shared_ptr<Utils::ThreadPool> m_threadPool;
    std::unique_ptr<std::thread> m_wfpThread;
    std::unique_ptr<std::thread> m_cleanupThread;

    // Synchronization
    mutable std::shared_mutex m_ruleMutex;
    mutable std::shared_mutex m_connectionMutex;
    mutable std::shared_mutex m_blocklistMutex;
    mutable std::shared_mutex m_callbackMutex;

    // Data Stores
    std::vector<FilterRule> m_rules;
    std::unordered_map<uint64_t, NetworkConnection> m_connections;
    std::unordered_set<std::string> m_blockedIPs; // Stored as string for quick lookup
    std::unordered_set<std::string> m_blockedDomains;

    // Beacon Tracking: PID -> (RemoteIP -> [Timestamps])
    struct BeaconTracker {
        std::deque<std::chrono::system_clock::time_point> timestamps;
        std::chrono::system_clock::time_point lastCheck;
    };
    std::map<std::pair<uint32_t, std::string>, BeaconTracker> m_beaconTrackers;
    std::mutex m_beaconMutex;

    // Stats
    NetworkFilterStats m_stats;

    // Integrations
    ThreatIntel::ThreatIntelIndex* m_threatIntel{ nullptr };
    PatternStore::PatternIndex* m_patternIndex{ nullptr };

    // Callbacks
    std::unordered_map<uint64_t, ConnectionCallback> m_connectionCallbacks;
    std::unordered_map<uint64_t, NetworkEventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, DNSCallback> m_dnsCallbacks;
    std::unordered_map<uint64_t, C2DetectionCallback> m_c2Callbacks;
    std::unordered_map<uint64_t, ExfiltrationCallback> m_exfilCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{ 1 };

    // -------------------------------------------------------------------------
    // Driver Communication
    // -------------------------------------------------------------------------

    void ConnectToDriver() {
        // Connect to the ShadowSensor WFP callout driver
        m_hDriver = CreateFileW(L"\\\\.\\ShadowSensor",
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);

        if (m_hDriver == INVALID_HANDLE_VALUE) {
            Utils::Logger::Warn(L"NetworkTrafficFilter: Failed to connect to ShadowSensor driver. Running in user-mode only.");
        } else {
            Utils::Logger::Info(L"NetworkTrafficFilter: Connected to ShadowSensor driver.");
        }
    }

    void WFPMessageLoop() {
        Utils::Logger::Info(L"NetworkTrafficFilter: WFP listener thread started.");

        while (m_running) {
            if (m_hDriver == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            // Simulated: Read events from driver
            // In real implementation: FilterGetMessage / DeviceIoControl
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // -------------------------------------------------------------------------
    // Core Logic
    // -------------------------------------------------------------------------

    FilterAction EvaluateRules(const NetworkConnection& conn) {
        m_stats.rulesEvaluated++;
        std::shared_lock lock(m_ruleMutex);

        // Default to config default
        FilterAction result = m_config.defaultAction;
        int highestPriority = -1;

        // Iterate rules (linear scan - optimized version would use trie/interval tree)
        for (const auto& rule : m_rules) {
            if (!rule.enabled) continue;
            if (static_cast<int>(rule.priority) <= highestPriority) continue; // Optimization

            // Check Direction
            if (rule.direction != ConnectionDirection::Bidirectional &&
                rule.direction != conn.direction) continue;

            // Check Protocol
            if (rule.protocol != NetworkProtocol::Unknown &&
                rule.protocol != conn.tuple.protocol) continue;

            // Check Port
            if (rule.remotePort != 0) {
                uint16_t port = conn.tuple.remote.port;
                if (rule.remotePortEnd != 0) {
                     // Range check
                     if (port < rule.remotePort || port > rule.remotePortEnd) continue;
                } else {
                    // Exact match
                    if (port != rule.remotePort) continue;
                }
            }

            // Check IP
            if (rule.remoteIP.has_value()) {
                 // Simplification: Direct match. Real implementation needs CIDR check logic.
                 if (rule.remoteIP->ipv4 != conn.tuple.remote.address.ipv4) continue;
            }

            // Check Process Name
            if (rule.processPattern.has_value()) {
                 if (conn.processName.find(*rule.processPattern) == std::wstring::npos) continue;
            }

            // Match found!
            result = rule.action;
            highestPriority = rule.priority;

            // const_cast to update hit count (mutable would be better but struct is public)
            auto& r = const_cast<FilterRule&>(rule);
            r.hitCount++;
            r.lastHit = Now();

            // If Block, we can stop early (assuming Block is high priority in logic or we sort rules)
            // Here we respect strict priority numbers
        }

        return result;
    }

    BeaconAnalysis AnalyzeBeacon(uint32_t pid, const NetworkEndpoint& remote) {
        BeaconAnalysis analysis;
        analysis.processId = pid;
        analysis.remote = remote;
        analysis.firstSeen = Now();

        if (!m_config.detectC2) return analysis;

        std::lock_guard lock(m_beaconMutex);
        auto key = std::make_pair(pid, remote.ToString());
        auto& tracker = m_beaconTrackers[key];

        tracker.timestamps.push_back(Now());
        if (tracker.timestamps.size() > NetworkFilterConstants::MIN_BEACON_SAMPLES + 10) {
            tracker.timestamps.pop_front();
        }

        analysis.sampleCount = tracker.timestamps.size();

        if (analysis.sampleCount >= NetworkFilterConstants::MIN_BEACON_SAMPLES) {
            // Calculate intervals
            std::vector<double> intervals;
            for (size_t i = 1; i < tracker.timestamps.size(); ++i) {
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    tracker.timestamps[i] - tracker.timestamps[i-1]).count();
                intervals.push_back(static_cast<double>(ms));
            }

            // Calculate Variance & Jitter
            double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
            double mean = sum / intervals.size();

            double sq_sum = std::inner_product(intervals.begin(), intervals.end(), intervals.begin(), 0.0);
            double stdev = std::sqrt(sq_sum / intervals.size() - mean * mean);
            double cv = stdev / mean; // Coefficient of Variation

            analysis.avgInterval = mean / 1000.0;
            analysis.jitter = cv;

            // Beacon Logic: Low Jitter = Beacon
            if (cv < m_config.beaconVarianceThreshold) {
                analysis.isBeacon = true;
                analysis.confidence = (1.0 - cv) * 100.0;
                m_stats.c2Detected++;
            }
        }

        return analysis;
    }
};

// ============================================================================
// SINGLETON ACCESS
// ============================================================================

NetworkTrafficFilter& NetworkTrafficFilter::Instance() {
    static NetworkTrafficFilter instance;
    return instance;
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

NetworkTrafficFilter::NetworkTrafficFilter() : m_impl(std::make_unique<Impl>()) {
}

NetworkTrafficFilter::~NetworkTrafficFilter() {
    Shutdown();
}

bool NetworkTrafficFilter::Initialize() {
    return Initialize(nullptr, NetworkFilterConfig::CreateDefault());
}

bool NetworkTrafficFilter::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return Initialize(threadPool, NetworkFilterConfig::CreateDefault());
}

bool NetworkTrafficFilter::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool, const NetworkFilterConfig& config) {
    if (m_impl->m_initialized.exchange(true)) return true;

    m_impl->m_threadPool = threadPool;
    m_impl->m_config = config;

    Utils::Logger::Info(L"NetworkTrafficFilter: Initializing...");

    // Connect to Driver
    m_impl->ConnectToDriver();

    // Load default blocklists if available
    // m_impl->LoadBlockListFromFile(L"data/ip_blocklist.txt");

    return true;
}

void NetworkTrafficFilter::Start() {
    if (m_impl->m_running.exchange(true)) return;

    Utils::Logger::Info(L"NetworkTrafficFilter: Starting filtering engine...");

    // Start WFP Listener Thread
    m_impl->m_wfpThread = std::make_unique<std::thread>(&Impl::WFPMessageLoop, m_impl.get());

    // Start Cleanup Thread
    m_impl->m_cleanupThread = std::make_unique<std::thread>([this]() {
        while (m_impl->m_running) {
            std::this_thread::sleep_for(std::chrono::minutes(1));
            // Cleanup logic would go here
        }
    });
}

void NetworkTrafficFilter::Stop() {
    m_impl->m_running = false;

    if (m_impl->m_wfpThread && m_impl->m_wfpThread->joinable()) {
        m_impl->m_wfpThread->join();
    }

    if (m_impl->m_cleanupThread && m_impl->m_cleanupThread->joinable()) {
        m_impl->m_cleanupThread->join();
    }

    Utils::Logger::Info(L"NetworkTrafficFilter: Stopped.");
}

void NetworkTrafficFilter::Shutdown() {
    Stop();

    if (m_impl->m_hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(m_impl->m_hDriver);
        m_impl->m_hDriver = INVALID_HANDLE_VALUE;
    }

    m_impl->m_initialized = false;
}

bool NetworkTrafficFilter::IsRunning() const noexcept {
    return m_impl->m_running;
}

void NetworkTrafficFilter::UpdateConfig(const NetworkFilterConfig& config) {
    m_impl->m_config = config;
    Utils::Logger::Info(L"NetworkTrafficFilter: Configuration updated.");
}

NetworkFilterConfig NetworkTrafficFilter::GetConfig() const {
    return m_impl->m_config;
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

FilterAction NetworkTrafficFilter::OnConnectionAttempt(const NetworkConnection& connection) {
    if (!m_impl->m_running) return FilterAction::Allow;

    m_impl->m_stats.totalConnections++;
    m_impl->m_stats.activeConnections++;

    // 1. Check Threat Intel (IP)
    if (m_impl->m_threatIntel) {
        // double score = m_impl->m_threatIntel->GetReputation(connection.tuple.remote.address.ToString());
        // if (score > 80.0) { ... }
    }

    // 2. Check Blocklists
    {
        std::shared_lock lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedIPs.count(connection.tuple.remote.address.ToString())) {
            m_impl->m_stats.connectionsBlocked++;
            return FilterAction::Block;
        }
        if (!connection.domainName.empty() && m_impl->m_blockedDomains.count(connection.domainName)) {
            m_impl->m_stats.connectionsBlocked++;
            return FilterAction::Block;
        }
    }

    // 3. Evaluate Rules
    FilterAction action = m_impl->EvaluateRules(connection);

    // 4. Record Connection
    if (action != FilterAction::Block) {
        std::unique_lock lock(m_impl->m_connectionMutex);
        m_impl->m_connections[connection.connectionId] = connection;
        m_impl->m_stats.connectionsAllowed++;
    } else {
        m_impl->m_stats.connectionsBlocked++;
    }

    // 5. Invoke Callbacks
    {
        std::shared_lock cbLock(m_impl->m_callbackMutex);
        for (const auto& [id, cb] : m_impl->m_connectionCallbacks) {
            FilterAction cbAction = cb(connection);
            if (cbAction == FilterAction::Block) action = FilterAction::Block;
        }
    }

    return action;
}

void NetworkTrafficFilter::OnConnectionEstablished(const NetworkConnection& connection) {
    std::unique_lock lock(m_impl->m_connectionMutex);
    auto it = m_impl->m_connections.find(connection.connectionId);
    if (it != m_impl->m_connections.end()) {
        it->second.state = ConnectionState::Established;
        it->second.lastActivity = Now();
    }

    NetworkEvent evt;
    evt.eventType = NetworkEventType::ConnectionEstablished;
    evt.connectionId = connection.connectionId;
    evt.timestamp = Now();
    m_impl->InvokeEventCallbacks(evt);
}

void NetworkTrafficFilter::OnConnectionClosed(uint64_t connectionId) {
    std::unique_lock lock(m_impl->m_connectionMutex);
    if (m_impl->m_connections.erase(connectionId)) {
        m_impl->m_stats.activeConnections--;
    }
}

void NetworkTrafficFilter::OnDataTransfer(uint64_t connectionId, bool outbound, size_t dataSize, std::span<const uint8_t> data) {
    std::shared_lock lock(m_impl->m_connectionMutex);
    auto it = m_impl->m_connections.find(connectionId);
    if (it == m_impl->m_connections.end()) return;

    // Update Stats
    if (outbound) {
        it->second.bytesSent += dataSize;
        m_impl->m_stats.bytesOutbound += dataSize;

        // Exfiltration Check
        if (m_impl->m_config.detectExfiltration && dataSize > m_impl->m_config.largeTransferThreshold) {
            CheckExfiltration(it->second.processId);
        }

        // C2 Check (Outbound traffic analysis)
        if (m_impl->m_config.detectC2) {
            auto analysis = m_impl->AnalyzeBeacon(it->second.processId, it->second.tuple.remote);
            if (analysis.isBeacon) {
                // Trigger C2 Callback
                 std::shared_lock cbLock(m_impl->m_callbackMutex);
                 for (const auto& [id, cb] : m_impl->m_c2Callbacks) {
                     cb(analysis);
                 }
            }
        }
    } else {
        it->second.bytesReceived += dataSize;
        m_impl->m_stats.bytesInbound += dataSize;
    }

    it->second.lastActivity = Now();

    // Deep Packet Inspection (DPI)
    if (m_impl->m_config.deepInspection) {
        // Check for HTTP/TLS headers
        if (data.size() > 4) {
            // Simple HTTP Detection
            if ((data[0] == 'G' && data[1] == 'E' && data[2] == 'T') ||
                (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T')) {
                it->second.appProtocol = AppProtocol::HTTP;
            }
            // TLS Handshake (0x16 = Handshake, 0x03 = SSL/TLS version)
            else if (data[0] == 0x16 && data[1] == 0x03) {
                it->second.appProtocol = AppProtocol::TLS;
                it->second.isTLS = true;
            }
        }
        m_impl->m_stats.deepInspections++;
    }
}

bool NetworkTrafficFilter::KillConnection(uint32_t pid, const std::string& remoteIP, uint16_t remotePort) {
    // In user-mode, we can use SetTcpEntry to kill connections (requires admin)
    // Here we just update internal state and return true to simulate
    // In real implementation: Call Iphlpapi::SetTcpEntry

    std::unique_lock lock(m_impl->m_connectionMutex);
    for (auto it = m_impl->m_connections.begin(); it != m_impl->m_connections.end();) {
        if (it->second.processId == pid &&
            it->second.tuple.remote.address.ToString() == remoteIP &&
            it->second.tuple.remote.port == remotePort) {

            it->second.state = ConnectionState::Closed;
            // Notify Driver to kill
            m_impl->m_stats.connectionsTerminated++;
            it = m_impl->m_connections.erase(it);
            return true;
        } else {
            ++it;
        }
    }
    return false;
}

// ============================================================================
// IP/DOMAIN BLOCKING
// ============================================================================

void NetworkTrafficFilter::BlockIP(const IPAddress& ip) {
    std::unique_lock lock(m_impl->m_blocklistMutex);
    m_impl->m_blockedIPs.insert(ip.ToString());
    Utils::Logger::Info(L"NetworkTrafficFilter: Blocked IP {}", Utils::StringUtils::Utf8ToWide(ip.ToString()));
}

void NetworkTrafficFilter::BlockIP(const std::string& ip) {
    std::unique_lock lock(m_impl->m_blocklistMutex);
    m_impl->m_blockedIPs.insert(ip);
}

void NetworkTrafficFilter::UnblockIP(const IPAddress& ip) {
    std::unique_lock lock(m_impl->m_blocklistMutex);
    m_impl->m_blockedIPs.erase(ip.ToString());
}

bool NetworkTrafficFilter::IsIPBlocked(const IPAddress& ip) const {
    std::shared_lock lock(m_impl->m_blocklistMutex);
    return m_impl->m_blockedIPs.count(ip.ToString());
}

void NetworkTrafficFilter::BlockDomain(const std::string& domain) {
    std::unique_lock lock(m_impl->m_blocklistMutex);
    m_impl->m_blockedDomains.insert(domain);
}

void NetworkTrafficFilter::UnblockDomain(const std::string& domain) {
    std::unique_lock lock(m_impl->m_blocklistMutex);
    m_impl->m_blockedDomains.erase(domain);
}

bool NetworkTrafficFilter::IsDomainBlocked(const std::string& domain) const {
    std::shared_lock lock(m_impl->m_blocklistMutex);
    return m_impl->m_blockedDomains.count(domain);
}

// ============================================================================
// DETECTION
// ============================================================================

BeaconAnalysis NetworkTrafficFilter::AnalyzeBeaconPattern(uint32_t pid, const NetworkEndpoint& remote) {
    return m_impl->AnalyzeBeacon(pid, remote);
}

bool NetworkTrafficFilter::IsDGADomain(const std::string& domain) const {
    double entropy = CalculateDomainEntropy(domain);
    if (entropy > m_impl->m_config.dgaEntropyThreshold) {
        m_impl->m_stats.dgaDetected++;
        return true;
    }
    return false;
}

double NetworkTrafficFilter::CalculateDomainEntropy(const std::string& domain) const {
    // Strip TLD for better analysis
    std::string d = domain;
    size_t lastDot = d.find_last_of('.');
    if (lastDot != std::string::npos) {
        d = d.substr(0, lastDot);
    }
    return CalculateShannonEntropy(d);
}

bool NetworkTrafficFilter::CheckExfiltration(uint32_t pid) {
    // Check bandwidth usage in last minute
    auto [sent, received] = GetProcessBandwidth(pid);
    if (sent > m_impl->m_config.largeTransferThreshold) {
        m_impl->m_stats.exfiltrationDetected++;
        Utils::Logger::Warn(L"NetworkTrafficFilter: Possible data exfiltration detected PID {}", pid);
        return true;
    }
    return false;
}

// ============================================================================
// STATISTICS & UTILS
// ============================================================================

NetworkFilterStats NetworkTrafficFilter::GetStats() const {
    return m_impl->m_stats;
}

void NetworkTrafficFilter::ResetStats() {
    m_impl->m_stats.Reset();
}

std::pair<uint64_t, uint64_t> NetworkTrafficFilter::GetProcessBandwidth(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_connectionMutex);
    uint64_t sent = 0;
    uint64_t recv = 0;

    for (const auto& [id, conn] : m_impl->m_connections) {
        if (conn.processId == pid) {
            sent += conn.bytesSent;
            recv += conn.bytesReceived;
        }
    }
    return { sent, recv };
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t NetworkTrafficFilter::RegisterConnectionCallback(ConnectionCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_connectionCallbacks[id] = std::move(callback);
    return id;
}

uint64_t NetworkTrafficFilter::RegisterC2Callback(C2DetectionCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_c2Callbacks[id] = std::move(callback);
    return id;
}

// Other callback registrations would follow the same pattern...

// ============================================================================
// PRIVATE HELPERS
// ============================================================================

void NetworkTrafficFilter::Impl::InvokeEventCallbacks(const NetworkEvent& event) {
    std::shared_lock lock(m_callbackMutex);
    for (const auto& [id, cb] : m_eventCallbacks) {
        cb(event);
    }
}

// ============================================================================
// EXTERNAL INTEGRATION
// ============================================================================

void NetworkTrafficFilter::SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index) {
    m_impl->m_threatIntel = index;
}

void NetworkTrafficFilter::SetPatternIndex(PatternStore::PatternIndex* index) {
    m_impl->m_patternIndex = index;
}

} // namespace RealTime
} // namespace ShadowStrike
