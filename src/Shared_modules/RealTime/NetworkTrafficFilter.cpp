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
// FILTER MANAGER USER-MODE API (must precede MessageProtocol.h)
// ============================================================================
// Include fltUser.h FIRST so that __FLT_USER_STRUCTURES_H__ is defined before
// MessageProtocol.h is parsed. This prevents MessageProtocol.h from creating
// a typedef alias for FILTER_MESSAGE_HEADER that conflicts with the OS definition.
#include <fltUser.h>
#pragma comment(lib, "fltlib.lib")

// ============================================================================
// KERNEL SHARED PROTOCOL TYPES
// ============================================================================
#pragma warning(push)
#pragma warning(disable: 4005)  // DNS_TYPE_* macros already defined in windns.h
#include "../../../PhantomSensor/Shared/NetworkTypes.h"
#pragma warning(pop)
#include "../../../PhantomSensor/Shared/MessageProtocol.h"
#include "../../../PhantomSensor/Shared/MessageTypes.h"
#include "../../../PhantomSensor/Shared/PortName.h"

// IP Helper for TCP connection termination
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

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
    // Configuration & State
    // -------------------------------------------------------------------------
    NetworkFilterConfig m_config;
    std::atomic<bool>   m_initialized{ false };
    std::atomic<bool>   m_running{ false };
    std::atomic<bool>   m_stopRequested{ false };

    // -------------------------------------------------------------------------
    // Driver Handle (minifilter communication port)
    // -------------------------------------------------------------------------
    HANDLE m_hPort{ INVALID_HANDLE_VALUE };
    HANDLE m_hCompletionPort{ nullptr };

    // -------------------------------------------------------------------------
    // Threading
    // -------------------------------------------------------------------------
    std::shared_ptr<Utils::ThreadPool> m_threadPool;
    std::unique_ptr<std::thread>       m_wfpThread;
    std::unique_ptr<std::thread>       m_cleanupThread;

    // -------------------------------------------------------------------------
    // Synchronization
    // -------------------------------------------------------------------------
    mutable std::shared_mutex m_ruleMutex;
    mutable std::shared_mutex m_connectionMutex;
    mutable std::shared_mutex m_blocklistMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_historyMutex;
    mutable std::shared_mutex m_dnsMutex;
    mutable std::shared_mutex m_eventMutex;

    // -------------------------------------------------------------------------
    // Data Stores
    // -------------------------------------------------------------------------
    std::vector<FilterRule>                              m_rules;
    std::unordered_map<uint64_t, NetworkConnection>      m_connections;
    std::unordered_set<std::string>                      m_blockedIPs;
    std::unordered_set<std::string>                      m_blockedDomains;

    // History (bounded deques)
    std::deque<NetworkConnection> m_connectionHistory;
    std::deque<NetworkEvent>      m_eventHistory;
    std::deque<DNSQueryEvent>     m_recentDNS;

    // -------------------------------------------------------------------------
    // Beacon Tracking: (PID, RemoteIP:port) -> interval deque
    // -------------------------------------------------------------------------
    struct BeaconTracker {
        std::deque<std::chrono::system_clock::time_point> timestamps;
        std::chrono::system_clock::time_point              firstSeen;
        std::chrono::system_clock::time_point              lastCheck;
        bool initialised{ false };
    };
    std::map<std::pair<uint32_t, std::string>, BeaconTracker> m_beaconTrackers;
    std::mutex m_beaconMutex;

    // -------------------------------------------------------------------------
    // Atomic Statistics (snapshotted by GetStats())
    // -------------------------------------------------------------------------
    std::atomic<uint64_t> m_statTotalConnections{ 0 };
    std::atomic<uint64_t> m_statConnectionsBlocked{ 0 };
    std::atomic<uint64_t> m_statConnectionsAllowed{ 0 };
    std::atomic<uint64_t> m_statConnectionsTerminated{ 0 };
    std::atomic<uint64_t> m_statBytesOutbound{ 0 };
    std::atomic<uint64_t> m_statBytesInbound{ 0 };
    std::atomic<uint64_t> m_statDnsQueries{ 0 };
    std::atomic<uint64_t> m_statDnsBlocked{ 0 };
    std::atomic<uint64_t> m_statC2Detected{ 0 };
    std::atomic<uint64_t> m_statDgaDetected{ 0 };
    std::atomic<uint64_t> m_statExfiltrationDetected{ 0 };
    std::atomic<uint64_t> m_statDeepInspections{ 0 };
    std::atomic<uint64_t> m_statRulesEvaluated{ 0 };
    std::atomic<uint64_t> m_statActiveConnections{ 0 };

    // -------------------------------------------------------------------------
    // Integrations
    // -------------------------------------------------------------------------
    ShadowStrike::ThreatIntel::ThreatIntelIndex* m_threatIntel{ nullptr };
    ShadowStrike::PatternStore::PatternIndex*    m_patternIndex{ nullptr };

    // -------------------------------------------------------------------------
    // Callbacks
    // -------------------------------------------------------------------------
    std::unordered_map<uint64_t, ConnectionCallback>    m_connectionCallbacks;
    std::unordered_map<uint64_t, NetworkEventCallback>  m_eventCallbacks;
    std::unordered_map<uint64_t, DNSCallback>           m_dnsCallbacks;
    std::unordered_map<uint64_t, C2DetectionCallback>   m_c2Callbacks;
    std::unordered_map<uint64_t, ExfiltrationCallback>  m_exfilCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{ 1 };

    // -------------------------------------------------------------------------
    // Driver Communication
    // -------------------------------------------------------------------------

    void ConnectToDriver() {
        Utils::Logger::Info("NetworkTrafficFilter: Connecting to driver port: {}",
            Utils::StringUtils::ToNarrow(SHADOWSTRIKE_PORT_NAME));

        HRESULT hr = FilterConnectCommunicationPort(
            SHADOWSTRIKE_PORT_NAME,
            0,
            nullptr,
            0,
            nullptr,
            &m_hPort
        );

        if (FAILED(hr)) {
            const DWORD err = HRESULT_CODE(hr);
            if (err == ERROR_FILE_NOT_FOUND) {
                Utils::Logger::Warn("NetworkTrafficFilter: Driver not installed (port not found). Running in user-mode only.");
            } else if (err == ERROR_ACCESS_DENIED) {
                Utils::Logger::Error("NetworkTrafficFilter: Access denied connecting to driver port.");
            } else {
                Utils::Logger::Error("NetworkTrafficFilter: FilterConnectCommunicationPort failed: 0x{:08X}", hr);
            }
            return;
        }

        // Create IOCP for the port so we can post a sentinel to unblock the thread on stop.
        m_hCompletionPort = CreateIoCompletionPort(
            m_hPort, nullptr, 0, 1);

        if (!m_hCompletionPort) {
            Utils::Logger::Error("NetworkTrafficFilter: CreateIoCompletionPort failed: {}", GetLastError());
            CloseHandle(m_hPort);
            m_hPort = INVALID_HANDLE_VALUE;
            return;
        }

        Utils::Logger::Info("NetworkTrafficFilter: Connected to driver port successfully.");
    }

    void DisconnectFromDriver() {
        if (m_hCompletionPort) {
            // Unblock any thread waiting on GetQueuedCompletionStatus
            PostQueuedCompletionStatus(m_hCompletionPort, 0, static_cast<ULONG_PTR>(~0ull), nullptr);
            CloseHandle(m_hCompletionPort);
            m_hCompletionPort = nullptr;
        }
        if (m_hPort != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hPort);
            m_hPort = INVALID_HANDLE_VALUE;
        }
    }

    void WFPMessageLoop() {
        Utils::Logger::Info("NetworkTrafficFilter: WFP listener thread started.");

        constexpr size_t kBufSize =
            sizeof(FILTER_MESSAGE_HEADER) +
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER) +
            sizeof(NETWORK_CONNECTION_EVENT);

        std::vector<uint8_t> buffer(kBufSize);
        auto* pOsHeader = reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.data());

        while (!m_stopRequested.load(std::memory_order_acquire)) {
            if (m_hPort == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            HRESULT hr = FilterGetMessage(
                m_hPort,
                pOsHeader,
                static_cast<DWORD>(kBufSize),
                nullptr   // synchronous; Stop() closes the port to unblock
            );

            if (m_stopRequested.load(std::memory_order_acquire)) break;

            if (FAILED(hr)) {
                if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                    hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                    break;   // Port closed – expected on shutdown
                }
                Utils::Logger::Error("NetworkTrafficFilter: FilterGetMessage failed: 0x{:08X}", hr);
                continue;
            }

            // Layout: [FILTER_MESSAGE_HEADER (OS)][SHADOWSTRIKE_MESSAGE_HEADER][payload]
            const auto* ssHeader = reinterpret_cast<const SHADOWSTRIKE_MESSAGE_HEADER*>(
                buffer.data() + sizeof(FILTER_MESSAGE_HEADER));

            if (ssHeader->Magic != SHADOWSTRIKE_MESSAGE_MAGIC) {
                Utils::Logger::Warn("NetworkTrafficFilter: Invalid message magic 0x{:08X}", ssHeader->Magic);
                continue;
            }

            const void* payload = buffer.data() +
                sizeof(FILTER_MESSAGE_HEADER) +
                sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

            switch (static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(ssHeader->MessageType)) {
                case FilterMessageType_NetworkAlert: {
                    const auto* evt = static_cast<const NETWORK_CONNECTION_EVENT*>(payload);
                    ProcessNetworkConnectionEvent(*evt, ssHeader->MessageId);
                    break;
                }
                default:
                    break;
            }
        }

        Utils::Logger::Info("NetworkTrafficFilter: WFP listener thread exiting.");
    }

    void ProcessNetworkConnectionEvent(const NETWORK_CONNECTION_EVENT& evt, uint64_t messageId) {
        NetworkConnection conn;
        conn.connectionId  = GenerateConnectionId();
        conn.processId     = evt.Header.ProcessId;
        conn.direction     = (evt.Header.Direction == NetworkDirection_Outbound)
                             ? ConnectionDirection::Outbound
                             : ConnectionDirection::Inbound;
        conn.tuple.protocol = NetworkProtocol::Unknown;
        if (evt.Header.Protocol == NetworkProtocol_TCP)      conn.tuple.protocol = NetworkProtocol::TCP;
        else if (evt.Header.Protocol == NetworkProtocol_UDP) conn.tuple.protocol = NetworkProtocol::UDP;

        if (evt.LocalAddress.Address.Family == AF_INET) {
            conn.tuple.local.address.version = IPVersion::IPv4;
            conn.tuple.local.address.ipv4    = evt.LocalAddress.Address.V4.Address;
            conn.tuple.remote.address.version = IPVersion::IPv4;
            conn.tuple.remote.address.ipv4    = evt.RemoteAddress.Address.V4.Address;
        } else {
            conn.tuple.local.address.version = IPVersion::IPv6;
            std::memcpy(conn.tuple.local.address.ipv6.data(),
                        evt.LocalAddress.Address.V6.Bytes, 16);
            conn.tuple.remote.address.version = IPVersion::IPv6;
            std::memcpy(conn.tuple.remote.address.ipv6.data(),
                        evt.RemoteAddress.Address.V6.Bytes, 16);
        }
        conn.tuple.local.port  = ntohs(evt.LocalAddress.Port);
        conn.tuple.remote.port = ntohs(evt.RemoteAddress.Port);
        conn.creationTime      = Now();
        conn.lastActivity      = Now();

        if (evt.RemoteHostname[0] != L'\0') {
            conn.domainName = Utils::StringUtils::ToNarrow(evt.RemoteHostname);
        }
        if (evt.ProcessImagePath[0] != L'\0') {
            conn.processName = evt.ProcessImagePath;
        } else if (auto name = Utils::ProcessUtils::GetProcessName(evt.Header.ProcessId)) {
            conn.processName = *name;
        }

        // Evaluate and respond
        // First check blocklists (bypassed in original path — CRITICAL)
        FilterAction action = FilterAction::Allow;
        {
            std::shared_lock lock(m_blocklistMutex);
            if (m_blockedIPs.count(conn.tuple.remote.address.ToString())) {
                action = FilterAction::Block;
            }
            if (action != FilterAction::Block && !conn.domainName.empty()) {
                std::string lower = conn.domainName;
                for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
                if (m_blockedDomains.count(lower)) {
                    action = FilterAction::Block;
                }
            }
        }

        // Then evaluate rules if blocklist didn't block
        if (action != FilterAction::Block) {
            action = EvaluateRules(conn);
        }

        // Send verdict back
        struct {
            FILTER_REPLY_HEADER  ReplyHeader;
            uint32_t             Verdict;
        } reply{};
        reply.ReplyHeader.MessageId  = messageId;
        reply.ReplyHeader.Status     = S_OK;
        reply.Verdict                = (action == FilterAction::Block) ? 1u : 0u;
        FilterReplyMessage(m_hPort, &reply.ReplyHeader, sizeof(reply));
    }

    // -------------------------------------------------------------------------
    // Core Logic
    // -------------------------------------------------------------------------

    FilterAction EvaluateRules(const NetworkConnection& conn) {
        m_statRulesEvaluated++;
        std::shared_lock lock(m_ruleMutex);

        FilterAction result       = m_config.defaultAction;
        uint32_t     highestPrio  = 0;
        bool         matched      = false;

        for (const auto& rule : m_rules) {
            if (!rule.enabled) continue;
            if (matched && rule.priority <= highestPrio) continue;

            // Direction
            if (rule.direction != ConnectionDirection::Bidirectional &&
                rule.direction != conn.direction) continue;

            // Protocol
            if (rule.protocol != NetworkProtocol::Unknown &&
                rule.protocol != conn.tuple.protocol) continue;

            // Port (exact or range)
            if (rule.remotePort != 0) {
                const uint16_t port = conn.tuple.remote.port;
                if (rule.remotePortEnd != 0) {
                    if (port < rule.remotePort || port > rule.remotePortEnd) continue;
                } else {
                    if (port != rule.remotePort) continue;
                }
            }

            // IP (exact IPv4 match; CIDR can be added via subnet mask)
            if (rule.remoteIP.has_value()) {
                const auto& rip = *rule.remoteIP;
                if (rip.version == IPVersion::IPv4 &&
                    conn.tuple.remote.address.version == IPVersion::IPv4) {
                    if (rule.remoteSubnetBits > 0 && rule.remoteSubnetBits < 32) {
                        const uint32_t mask = ~((1u << (32 - rule.remoteSubnetBits)) - 1u);
                        if ((ntohl(rip.ipv4) & mask) != (ntohl(conn.tuple.remote.address.ipv4) & mask))
                            continue;
                    } else {
                        if (rip.ipv4 != conn.tuple.remote.address.ipv4) continue;
                    }
                } else if (rip.version == IPVersion::IPv6 &&
                           conn.tuple.remote.address.version == IPVersion::IPv6) {
                    if (rip.ipv6 != conn.tuple.remote.address.ipv6) continue;
                } else {
                    continue;
                }
            }

            // Domain pattern (simple suffix match)
            if (rule.domainPattern.has_value() && !conn.domainName.empty()) {
                const auto& pattern = *rule.domainPattern;
                if (!pattern.empty() && pattern[0] == '*') {
                    const std::string suffix = pattern.substr(1); // e.g. ".onion"
                    const size_t pos = conn.domainName.rfind(suffix);
                    if (pos == std::string::npos ||
                        pos + suffix.size() != conn.domainName.size()) continue;
                } else {
                    if (conn.domainName != pattern) continue;
                }
            }

            // Process name pattern
            if (rule.processPattern.has_value()) {
                if (conn.processName.find(*rule.processPattern) == std::wstring::npos)
                    continue;
            }

            // Time restriction
            if (rule.timeStart.has_value() && rule.timeEnd.has_value()) {
                const std::time_t t = std::time(nullptr);
                struct tm lt{};
                localtime_s(&lt, &t);
                const uint8_t h = static_cast<uint8_t>(lt.tm_hour);
                if (h < *rule.timeStart || h >= *rule.timeEnd) continue;
            }

            result       = rule.action;
            highestPrio  = rule.priority;
            matched      = true;

            rule.hitCount.fetch_add(1, std::memory_order_relaxed);
            rule.lastHitNs.store(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    Now().time_since_epoch()).count(),
                std::memory_order_relaxed);
        }

        return result;
    }

    BeaconAnalysis AnalyzeBeacon(uint32_t pid, const NetworkEndpoint& remote) {
        BeaconAnalysis analysis{};
        analysis.processId = pid;
        analysis.remote    = remote;

        if (!m_config.detectC2) return analysis;

        std::lock_guard lock(m_beaconMutex);
        auto key     = std::make_pair(pid, remote.ToString());
        auto& tracker = m_beaconTrackers[key];

        const auto now = Now();
        if (!tracker.initialised) {
            tracker.firstSeen   = now;
            tracker.initialised = true;
        }
        tracker.timestamps.push_back(now);

        // Keep a bounded window
        constexpr size_t kMaxSamples = NetworkFilterConstants::MIN_BEACON_SAMPLES + 20;
        while (tracker.timestamps.size() > kMaxSamples)
            tracker.timestamps.pop_front();

        analysis.sampleCount = tracker.timestamps.size();
        analysis.firstSeen   = tracker.firstSeen;
        analysis.lastSeen    = now;

        if (analysis.sampleCount < NetworkFilterConstants::MIN_BEACON_SAMPLES)
            return analysis;

        // Compute inter-arrival intervals (ms)
        std::vector<double> intervals;
        intervals.reserve(tracker.timestamps.size() - 1);
        for (size_t i = 1; i < tracker.timestamps.size(); ++i) {
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                tracker.timestamps[i] - tracker.timestamps[i - 1]).count();
            intervals.push_back(static_cast<double>(ms));
        }

        const double n    = static_cast<double>(intervals.size());
        const double sum  = std::accumulate(intervals.begin(), intervals.end(), 0.0);
        const double mean = sum / n;

        if (mean < 1.0) return analysis; // pathological – avoid div/0

        // Welford-style variance for numerical stability
        double M2 = 0.0;
        double mu = 0.0;
        for (size_t i = 0; i < intervals.size(); ++i) {
            const double delta = intervals[i] - mu;
            mu  += delta / static_cast<double>(i + 1);
            M2  += delta * (intervals[i] - mu);
        }
        const double variance = (intervals.size() > 1) ? M2 / static_cast<double>(intervals.size() - 1) : 0.0;
        const double stdev    = (variance > 0.0) ? std::sqrt(variance) : 0.0;
        const double cv       = stdev / mean; // Coefficient of Variation

        analysis.avgInterval = mean / 1000.0;
        analysis.jitter      = cv;

        if (cv < m_config.beaconVarianceThreshold) {
            analysis.isBeacon  = true;
            analysis.confidence = std::clamp((1.0 - cv) * 100.0, 0.0, 100.0);
            m_statC2Detected.fetch_add(1, std::memory_order_relaxed);
        }

        return analysis;
    }

    // -------------------------------------------------------------------------
    // Cleanup
    // -------------------------------------------------------------------------

    void CleanupStaleConnections() {
        const auto now     = Now();
        const auto timeout = m_config.connectionTimeout;

        std::unique_lock lock(m_connectionMutex);
        for (auto it = m_connections.begin(); it != m_connections.end(); ) {
            const auto idle = std::chrono::duration_cast<std::chrono::minutes>(
                now - it->second.lastActivity);
            if (idle >= timeout) {
                // Archive to history before removing
                {
                    std::unique_lock hLock(m_historyMutex);
                    if (m_connectionHistory.size() >= NetworkFilterConstants::MAX_CONNECTION_HISTORY)
                        m_connectionHistory.pop_front();
                    m_connectionHistory.push_back(it->second);
                }
                if (m_statActiveConnections.load(std::memory_order_relaxed) > 0)
                    m_statActiveConnections.fetch_sub(1, std::memory_order_relaxed);
                it = m_connections.erase(it);
            } else {
                ++it;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Callback Helpers
    // -------------------------------------------------------------------------

    void InvokeEventCallbacks(const NetworkEvent& evt) {
        // Copy callbacks under shared lock, invoke outside any lock
        std::vector<NetworkEventCallback> callbacks;
        {
            std::shared_lock lock(m_callbackMutex);
            callbacks.reserve(m_eventCallbacks.size());
            for (const auto& [id, cb] : m_eventCallbacks)
                callbacks.push_back(cb);
        }
        for (const auto& cb : callbacks) {
            try { cb(evt); } catch (...) {}
        }

        // Archive to event history
        std::unique_lock lock(m_eventMutex);
        if (m_eventHistory.size() >= NetworkFilterConstants::MAX_CONNECTION_HISTORY)
            m_eventHistory.pop_front();
        m_eventHistory.push_back(evt);
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
    m_impl->m_config     = config;

    Utils::Logger::Info("NetworkTrafficFilter: Initializing...");

    m_impl->ConnectToDriver();

    Utils::Logger::Info("NetworkTrafficFilter: Initialization complete.");
    return true;
}

void NetworkTrafficFilter::Start() {
    if (m_impl->m_running.exchange(true)) return;

    m_impl->m_stopRequested.store(false, std::memory_order_release);

    Utils::Logger::Info("NetworkTrafficFilter: Starting filtering engine...");

    m_impl->m_wfpThread = std::make_unique<std::thread>(
        &Impl::WFPMessageLoop, m_impl.get());

    m_impl->m_cleanupThread = std::make_unique<std::thread>([this]() {
        Utils::Logger::Info("NetworkTrafficFilter: Cleanup thread started.");
        while (!m_impl->m_stopRequested.load(std::memory_order_acquire)) {
            for (int i = 0; i < 60 && !m_impl->m_stopRequested.load(std::memory_order_acquire); ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!m_impl->m_stopRequested.load(std::memory_order_acquire))
                m_impl->CleanupStaleConnections();
        }
        Utils::Logger::Info("NetworkTrafficFilter: Cleanup thread exiting.");
    });
}

void NetworkTrafficFilter::Stop() {
    if (!m_impl->m_running.exchange(false)) return;

    m_impl->m_stopRequested.store(true, std::memory_order_release);

    // Close the port so FilterGetMessage unblocks immediately
    m_impl->DisconnectFromDriver();

    if (m_impl->m_wfpThread && m_impl->m_wfpThread->joinable())
        m_impl->m_wfpThread->join();

    if (m_impl->m_cleanupThread && m_impl->m_cleanupThread->joinable())
        m_impl->m_cleanupThread->join();

    Utils::Logger::Info("NetworkTrafficFilter: Stopped.");
}

void NetworkTrafficFilter::Shutdown() {
    Stop();
    m_impl->m_initialized.store(false, std::memory_order_release);
    Utils::Logger::Info("NetworkTrafficFilter: Shutdown complete.");
}

bool NetworkTrafficFilter::IsRunning() const noexcept {
    return m_impl->m_running.load(std::memory_order_relaxed);
}

void NetworkTrafficFilter::UpdateConfig(const NetworkFilterConfig& config) {
    // config is a value type – no mutex needed for the swap itself, but
    // we serialise against readers of m_config by using a brief exclusive lock
    // on an existing mutex.  We re-use m_ruleMutex as the config guard.
    {
        std::unique_lock lock(m_impl->m_ruleMutex);
        m_impl->m_config = config;
    }
    Utils::Logger::Info("NetworkTrafficFilter: Configuration updated.");
}

NetworkFilterConfig NetworkTrafficFilter::GetConfig() const {
    std::shared_lock lock(m_impl->m_ruleMutex);
    return m_impl->m_config;
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

FilterAction NetworkTrafficFilter::OnConnectionAttempt(const NetworkConnection& connection) {
    if (!m_impl->m_running.load(std::memory_order_relaxed)) return FilterAction::Allow;

    m_impl->m_statTotalConnections.fetch_add(1, std::memory_order_relaxed);

    // --- Connection limit enforcement ---
    {
        std::shared_lock lock(m_impl->m_connectionMutex);
        if (m_impl->m_connections.size() >= m_impl->m_config.maxConnections) {
            Utils::Logger::Warn("NetworkTrafficFilter: Max tracked connections ({}) reached; dropping oldest.",
                m_impl->m_config.maxConnections);
            // We drop from the map under exclusive lock below – take it now
            lock.unlock();
            std::unique_lock wLock(m_impl->m_connectionMutex);
            if (!m_impl->m_connections.empty())
                m_impl->m_connections.erase(m_impl->m_connections.begin());
        }
    }

    // --- Threat Intel reputation check ---
    if (m_impl->m_threatIntel) {
        const std::string remoteStr = connection.tuple.remote.address.ToString();
        // ThreatIntelIndex::GetIPReputation returns score 0-100 (100 = trusted, 0 = malicious)
        // Adjust threshold as needed; scores below 30 are treated as malicious
        // (API: double GetIPReputation(const std::string& ip))
        // We wrap in try/catch to prevent a bad intel feed from crashing the filter
        try {
            // Uncomment once ThreatIntelIndex API is confirmed:
            // double score = m_impl->m_threatIntel->GetIPReputation(remoteStr);
            // if (score < 30.0 && m_impl->m_config.maliciousIPAction == FilterAction::Block) {
            //     m_impl->m_statConnectionsBlocked.fetch_add(1, std::memory_order_relaxed);
            //     SS_LOG_WARN(L"NetworkTrafficFilter", L"Blocking malicious IP %hs (score %.1f)",
            //                 remoteStr.c_str(), score);
            //     return FilterAction::Block;
            // }
            (void)remoteStr;
        } catch (...) {}
    }

    // --- Blocklists ---
    {
        std::shared_lock lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedIPs.count(connection.tuple.remote.address.ToString())) {
            m_impl->m_statConnectionsBlocked.fetch_add(1, std::memory_order_relaxed);
            return FilterAction::Block;
        }
        if (!connection.domainName.empty()) {
            std::string lower = connection.domainName;
            for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            if (m_impl->m_blockedDomains.count(lower)) {
                m_impl->m_statConnectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                return FilterAction::Block;
            }
        }
    }

    // --- Rule evaluation ---
    FilterAction action = m_impl->EvaluateRules(connection);

    // --- Invoke connection callbacks BEFORE recording (outside locks) ---
    // Callbacks may override verdict to Block; we must not record blocked connections as active
    {
        std::vector<ConnectionCallback> callbacks;
        {
            std::shared_lock cbLock(m_impl->m_callbackMutex);
            callbacks.reserve(m_impl->m_connectionCallbacks.size());
            for (const auto& [id, cb] : m_impl->m_connectionCallbacks)
                callbacks.push_back(cb);
        }
        for (const auto& cb : callbacks) {
            try {
                if (cb(connection) == FilterAction::Block)
                    action = FilterAction::Block;
            } catch (...) {}
        }
    }

    // --- Record or block (after final verdict is known) ---
    if (action != FilterAction::Block) {
        std::unique_lock lock(m_impl->m_connectionMutex);
        m_impl->m_connections[connection.connectionId] = connection;
        m_impl->m_statConnectionsAllowed.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_statActiveConnections.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_impl->m_statConnectionsBlocked.fetch_add(1, std::memory_order_relaxed);
    }

    return action;
}

void NetworkTrafficFilter::OnConnectionEstablished(const NetworkConnection& connection) {
    {
        std::unique_lock lock(m_impl->m_connectionMutex);
        auto it = m_impl->m_connections.find(connection.connectionId);
        if (it != m_impl->m_connections.end()) {
            it->second.state        = ConnectionState::Established;
            it->second.lastActivity = Now();
        }
    } // Release lock before invoking callbacks

    NetworkEvent evt;
    evt.eventType    = NetworkEventType::ConnectionEstablished;
    evt.connectionId = connection.connectionId;
    evt.processId    = connection.processId;
    evt.timestamp    = Now();
    m_impl->InvokeEventCallbacks(evt);
}

void NetworkTrafficFilter::OnConnectionClosed(uint64_t connectionId) {
    NetworkConnection archived;
    bool found = false;
    {
        std::unique_lock lock(m_impl->m_connectionMutex);
        auto it = m_impl->m_connections.find(connectionId);
        if (it != m_impl->m_connections.end()) {
            archived = it->second;
            found = true;
            m_impl->m_connections.erase(it);
            if (m_impl->m_statActiveConnections.load(std::memory_order_relaxed) > 0)
                m_impl->m_statActiveConnections.fetch_sub(1, std::memory_order_relaxed);
        }
    }
    if (found) {
        archived.state = ConnectionState::Closed;
        std::unique_lock hLock(m_impl->m_historyMutex);
        if (m_impl->m_connectionHistory.size() >= NetworkFilterConstants::MAX_CONNECTION_HISTORY)
            m_impl->m_connectionHistory.pop_front();
        m_impl->m_connectionHistory.push_back(archived);
    }
}

void NetworkTrafficFilter::OnDataTransfer(uint64_t connectionId, bool outbound, size_t dataSize, std::span<const uint8_t> data) {
    // Exclusive lock: we modify connection fields (bytesSent/Received, lastActivity, appProtocol, isTLS)
    std::unique_lock lock(m_impl->m_connectionMutex);
    auto it = m_impl->m_connections.find(connectionId);
    if (it == m_impl->m_connections.end()) return;

    if (outbound) {
        it->second.bytesSent += dataSize;
        m_impl->m_statBytesOutbound.fetch_add(dataSize, std::memory_order_relaxed);
    } else {
        it->second.bytesReceived += dataSize;
        m_impl->m_statBytesInbound.fetch_add(dataSize, std::memory_order_relaxed);
    }
    it->second.lastActivity = Now();

    // Deep Packet Inspection
    if (m_impl->m_config.deepInspection && data.size() >= 4) {
        if ((data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') ||
            (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') ||
            (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') ||
            (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') ||
            (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E')) {
            it->second.appProtocol = AppProtocol::HTTP;
        } else if (data[0] == 0x16 && data[1] == 0x03 && data.size() >= 5) {
            it->second.appProtocol = AppProtocol::TLS;
            it->second.isTLS       = true;
            // TLS version from record header
            it->second.tlsVersion  = static_cast<uint16_t>((data[1] << 8) | data[2]);
        }
        m_impl->m_statDeepInspections.fetch_add(1, std::memory_order_relaxed);
    }

    // Snapshot connection for out-of-lock work
    const uint32_t pid    = it->second.processId;
    const auto     remote = it->second.tuple.remote;
    lock.unlock();

    // Exfiltration check (outside connection lock)
    if (outbound && m_impl->m_config.detectExfiltration &&
        dataSize > m_impl->m_config.largeTransferThreshold) {
        CheckExfiltration(pid);
    }

    // C2 beacon analysis (outside connection lock)
    if (outbound && m_impl->m_config.detectC2) {
        auto analysis = m_impl->AnalyzeBeacon(pid, remote);
        if (analysis.isBeacon) {
            std::vector<C2DetectionCallback> callbacks;
            {
                std::shared_lock cbLock(m_impl->m_callbackMutex);
                callbacks.reserve(m_impl->m_c2Callbacks.size());
                for (const auto& [id, cb] : m_impl->m_c2Callbacks)
                    callbacks.push_back(cb);
            }
            for (const auto& cb : callbacks) {
                try { cb(analysis); } catch (...) {}
            }
        }
    }
}

bool NetworkTrafficFilter::KillConnection(uint32_t pid, const std::string& remoteIP, uint16_t remotePort) {
    std::unique_lock lock(m_impl->m_connectionMutex);
    for (auto it = m_impl->m_connections.begin(); it != m_impl->m_connections.end(); ++it) {
        if (it->second.processId == pid &&
            it->second.tuple.remote.address.ToString() == remoteIP &&
            it->second.tuple.remote.port == remotePort &&
            it->second.tuple.protocol == NetworkProtocol::TCP) {

            // Only use SetTcpEntry for IPv4 — it doesn't support IPv6
            if (it->second.tuple.remote.address.version == IPVersion::IPv6) {
                Utils::Logger::Warn("NetworkTrafficFilter: KillConnection for IPv6 TCP (PID {} → {}:{})"
                    " — removing from tracker only.", pid, remoteIP, remotePort);
            } else {
                MIB_TCPROW row{};
                row.dwState       = MIB_TCP_STATE_DELETE_TCB;
                row.dwLocalAddr   = it->second.tuple.local.address.ipv4;
                row.dwLocalPort   = htons(it->second.tuple.local.port);
                row.dwRemoteAddr  = it->second.tuple.remote.address.ipv4;
                row.dwRemotePort  = htons(it->second.tuple.remote.port);

                const DWORD err = SetTcpEntry(&row);
                if (err != NO_ERROR && err != ERROR_MR_MID_NOT_FOUND) {
                    Utils::Logger::Warn("NetworkTrafficFilter: SetTcpEntry failed ({}); removing from tracker only.", err);
                }
            }

            it->second.state = ConnectionState::Closed;
            m_impl->m_statConnectionsTerminated.fetch_add(1, std::memory_order_relaxed);
            if (m_impl->m_statActiveConnections.load(std::memory_order_relaxed) > 0)
                m_impl->m_statActiveConnections.fetch_sub(1, std::memory_order_relaxed);
            m_impl->m_connections.erase(it);
            return true;
        }
    }
    return false;
}

bool NetworkTrafficFilter::KillConnection(uint64_t connectionId) {
    std::unique_lock lock(m_impl->m_connectionMutex);
    auto it = m_impl->m_connections.find(connectionId);
    if (it == m_impl->m_connections.end()) return false;

    if (it->second.tuple.protocol == NetworkProtocol::TCP) {
        if (it->second.tuple.remote.address.version == IPVersion::IPv6) {
            Utils::Logger::Warn("NetworkTrafficFilter: KillConnection for IPv6 TCP (connId {}) "
                "— SetTcpEntry only supports IPv4; removing from tracker only.", connectionId);
        } else {
            MIB_TCPROW row{};
            row.dwState       = MIB_TCP_STATE_DELETE_TCB;
            row.dwLocalAddr   = it->second.tuple.local.address.ipv4;
            row.dwLocalPort   = htons(it->second.tuple.local.port);
            row.dwRemoteAddr  = it->second.tuple.remote.address.ipv4;
            row.dwRemotePort  = htons(it->second.tuple.remote.port);
            const DWORD err = SetTcpEntry(&row);
            if (err != NO_ERROR && err != ERROR_MR_MID_NOT_FOUND) {
                Utils::Logger::Warn("NetworkTrafficFilter: SetTcpEntry failed for connId {} ({})", connectionId, err);
            }
        }
    }

    m_impl->m_statConnectionsTerminated.fetch_add(1, std::memory_order_relaxed);
    if (m_impl->m_statActiveConnections.load(std::memory_order_relaxed) > 0)
        m_impl->m_statActiveConnections.fetch_sub(1, std::memory_order_relaxed);
    m_impl->m_connections.erase(it);
    return true;
}

size_t NetworkTrafficFilter::KillProcessConnections(uint32_t pid) {
    std::unique_lock lock(m_impl->m_connectionMutex);
    size_t killed = 0;
    for (auto it = m_impl->m_connections.begin(); it != m_impl->m_connections.end(); ) {
        if (it->second.processId == pid) {
            if (it->second.tuple.protocol == NetworkProtocol::TCP &&
                it->second.tuple.remote.address.version != IPVersion::IPv6) {
                MIB_TCPROW row{};
                row.dwState       = MIB_TCP_STATE_DELETE_TCB;
                row.dwLocalAddr   = it->second.tuple.local.address.ipv4;
                row.dwLocalPort   = htons(it->second.tuple.local.port);
                row.dwRemoteAddr  = it->second.tuple.remote.address.ipv4;
                row.dwRemotePort  = htons(it->second.tuple.remote.port);
                SetTcpEntry(&row); // Best-effort; ignore individual errors
            }
            m_impl->m_statConnectionsTerminated.fetch_add(1, std::memory_order_relaxed);
            if (m_impl->m_statActiveConnections.load(std::memory_order_relaxed) > 0)
                m_impl->m_statActiveConnections.fetch_sub(1, std::memory_order_relaxed);
            it = m_impl->m_connections.erase(it);
            ++killed;
        } else {
            ++it;
        }
    }
    if (killed > 0)
        Utils::Logger::Info("NetworkTrafficFilter: Killed {} connection(s) for PID {}.", killed, pid);
    return killed;
}

// ============================================================================
// IP/DOMAIN BLOCKING
// ============================================================================

void NetworkTrafficFilter::BlockIP(const IPAddress& ip) {
    const std::string ipStr = ip.ToString();
    {
        std::unique_lock lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedIPs.size() >= NetworkFilterConstants::MAX_BLOCKED_IPS) {
            Utils::Logger::Warn("NetworkTrafficFilter: Blocked IP list full ({} entries); cannot add {}.",
                NetworkFilterConstants::MAX_BLOCKED_IPS, ipStr);
            return;
        }
        m_impl->m_blockedIPs.insert(ipStr);
    }
    Utils::Logger::Info("NetworkTrafficFilter: Blocked IP {}.", ipStr);
}

void NetworkTrafficFilter::BlockIP(const std::string& ip) {
    if (ip.empty()) return;
    {
        std::unique_lock lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedIPs.size() >= NetworkFilterConstants::MAX_BLOCKED_IPS) {
            Utils::Logger::Warn("NetworkTrafficFilter: Blocked IP list full; cannot add {}.", ip);
            return;
        }
        m_impl->m_blockedIPs.insert(ip);
    }
    Utils::Logger::Info("NetworkTrafficFilter: Blocked IP {}.", ip);
}

void NetworkTrafficFilter::UnblockIP(const IPAddress& ip) {
    std::unique_lock lock(m_impl->m_blocklistMutex);
    m_impl->m_blockedIPs.erase(ip.ToString());
}

bool NetworkTrafficFilter::IsIPBlocked(const IPAddress& ip) const {
    std::shared_lock lock(m_impl->m_blocklistMutex);
    return m_impl->m_blockedIPs.count(ip.ToString()) > 0;
}

void NetworkTrafficFilter::BlockDomain(const std::string& domain) {
    if (domain.empty()) return;
    std::string lower = domain;
    for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    {
        std::unique_lock lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedDomains.size() >= NetworkFilterConstants::MAX_BLOCKED_DOMAINS) {
            Utils::Logger::Warn("NetworkTrafficFilter: Blocked domain list full; cannot add {}.", domain);
            return;
        }
        m_impl->m_blockedDomains.insert(lower);
    }
    Utils::Logger::Info("NetworkTrafficFilter: Blocked domain {}.", domain);
}

void NetworkTrafficFilter::UnblockDomain(const std::string& domain) {
    std::string lower = domain;
    for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    std::unique_lock lock(m_impl->m_blocklistMutex);
    m_impl->m_blockedDomains.erase(lower);
}

bool NetworkTrafficFilter::IsDomainBlocked(const std::string& domain) const {
    std::string lower = domain;
    for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    std::shared_lock lock(m_impl->m_blocklistMutex);
    return m_impl->m_blockedDomains.count(lower) > 0;
}

std::vector<IPAddress> NetworkTrafficFilter::GetBlockedIPs() const {
    std::shared_lock lock(m_impl->m_blocklistMutex);
    std::vector<IPAddress> result;
    result.reserve(m_impl->m_blockedIPs.size());
    for (const auto& s : m_impl->m_blockedIPs)
        result.push_back(IPAddress::FromString(s));
    return result;
}

std::vector<std::string> NetworkTrafficFilter::GetBlockedDomains() const {
    std::shared_lock lock(m_impl->m_blocklistMutex);
    return std::vector<std::string>(m_impl->m_blockedDomains.begin(),
                                    m_impl->m_blockedDomains.end());
}

bool NetworkTrafficFilter::LoadBlockListFromFile(const std::wstring& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        Utils::Logger::Error("NetworkTrafficFilter: Cannot open blocklist file: {}",
            Utils::StringUtils::ToNarrow(filePath));
        return false;
    }

    size_t loaded = 0;
    std::string line;
    while (std::getline(file, line)) {
        // Strip comments and whitespace
        if (const size_t hash = line.find('#'); hash != std::string::npos)
            line = line.substr(0, hash);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\r' || line.back() == '\t'))
            line.pop_back();
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.erase(line.begin());
        if (line.empty()) continue;

        // Heuristic: domain names contain '.' but no ':' in the typical IP/domain line
        // IP addresses are purely numeric+dots or hex+colons (IPv6)
        const bool looksLikeIP = (line.find(':') != std::string::npos) ||
            std::all_of(line.begin(), line.end(), [](char c) {
                return ::isdigit(static_cast<unsigned char>(c)) || c == '.';
            });

        if (looksLikeIP) {
            std::unique_lock lock(m_impl->m_blocklistMutex);
            if (m_impl->m_blockedIPs.size() < NetworkFilterConstants::MAX_BLOCKED_IPS) {
                m_impl->m_blockedIPs.insert(line);
                ++loaded;
            }
        } else {
            for (auto& c : line) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            std::unique_lock lock(m_impl->m_blocklistMutex);
            if (m_impl->m_blockedDomains.size() < NetworkFilterConstants::MAX_BLOCKED_DOMAINS) {
                m_impl->m_blockedDomains.insert(line);
                ++loaded;
            }
        }
    }

    Utils::Logger::Info("NetworkTrafficFilter: Loaded {} entries from blocklist.", loaded);
    return true;
}

// ============================================================================
// RULE MANAGEMENT
// ============================================================================

bool NetworkTrafficFilter::AddRule(const FilterRule& rule) {
    if (rule.ruleId.empty()) {
        Utils::Logger::Error("NetworkTrafficFilter: AddRule rejected – rule has empty ID.");
        return false;
    }
    std::unique_lock lock(m_impl->m_ruleMutex);
    if (m_impl->m_rules.size() >= NetworkFilterConstants::MAX_FILTER_RULES) {
        Utils::Logger::Warn("NetworkTrafficFilter: Rule limit reached; cannot add rule '{}'.", rule.ruleId);
        return false;
    }
    // Replace if exists
    for (auto& r : m_impl->m_rules) {
        if (r.ruleId == rule.ruleId) { r = rule; return true; }
    }
    m_impl->m_rules.push_back(rule);
    // Keep sorted by descending priority for fast early-exit
    std::stable_sort(m_impl->m_rules.begin(), m_impl->m_rules.end(),
        [](const FilterRule& a, const FilterRule& b) { return a.priority > b.priority; });
    return true;
}

bool NetworkTrafficFilter::RemoveRule(const std::string& ruleId) {
    std::unique_lock lock(m_impl->m_ruleMutex);
    auto it = std::find_if(m_impl->m_rules.begin(), m_impl->m_rules.end(),
        [&](const FilterRule& r) { return r.ruleId == ruleId; });
    if (it == m_impl->m_rules.end()) return false;
    m_impl->m_rules.erase(it);
    return true;
}

void NetworkTrafficFilter::SetRuleEnabled(const std::string& ruleId, bool enabled) {
    std::unique_lock lock(m_impl->m_ruleMutex);
    for (auto& r : m_impl->m_rules) {
        if (r.ruleId == ruleId) { r.enabled = enabled; return; }
    }
}

std::optional<FilterRule> NetworkTrafficFilter::GetRule(const std::string& ruleId) const {
    std::shared_lock lock(m_impl->m_ruleMutex);
    for (const auto& r : m_impl->m_rules)
        if (r.ruleId == ruleId) return r;
    return std::nullopt;
}

std::vector<FilterRule> NetworkTrafficFilter::GetRules() const {
    std::shared_lock lock(m_impl->m_ruleMutex);
    return m_impl->m_rules;
}

bool NetworkTrafficFilter::LoadRulesFromFile(const std::wstring& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        Utils::Logger::Error("NetworkTrafficFilter: Cannot open rules file: {}",
            Utils::StringUtils::ToNarrow(filePath));
        return false;
    }
    try {
        nlohmann::json j;
        file >> j;
        size_t loaded = 0;
        for (const auto& entry : j) {
            FilterRule rule;
            rule.ruleId   = entry.value("id", "");
            rule.name     = Utils::StringUtils::ToWide(entry.value("name", ""));
            rule.enabled  = entry.value("enabled", true);
            rule.priority = entry.value("priority", 0u);
            const std::string action = entry.value("action", "block");
            if (action == "allow")     rule.action = FilterAction::Allow;
            else if (action == "log")  rule.action = FilterAction::LogOnly;
            else                       rule.action = FilterAction::Block;
            const std::string dir = entry.value("direction", "outbound");
            if (dir == "inbound")        rule.direction = ConnectionDirection::Inbound;
            else if (dir == "both")      rule.direction = ConnectionDirection::Bidirectional;
            else                         rule.direction = ConnectionDirection::Outbound;
            if (entry.contains("remotePort"))
                rule.remotePort = static_cast<uint16_t>(entry["remotePort"].get<int>());
            if (entry.contains("domain"))
                rule.domainPattern = entry["domain"].get<std::string>();
            if (entry.contains("processName"))
                rule.processPattern = Utils::StringUtils::ToWide(entry["processName"].get<std::string>());
            rule.created = Now();
            if (AddRule(rule)) ++loaded;
        }
        Utils::Logger::Info("NetworkTrafficFilter: Loaded {} rules from file.", loaded);
        return true;
    } catch (const std::exception& ex) {
        Utils::Logger::Error("NetworkTrafficFilter: Failed to parse rules file: {}", ex.what());
        return false;
    }
}

bool NetworkTrafficFilter::SaveRulesToFile(const std::wstring& filePath) const {
    nlohmann::json j = nlohmann::json::array();
    {
        std::shared_lock lock(m_impl->m_ruleMutex);
        for (const auto& r : m_impl->m_rules) {
            nlohmann::json entry;
            entry["id"]       = r.ruleId;
            entry["name"]     = Utils::StringUtils::ToNarrow(r.name);
            entry["enabled"]  = r.enabled;
            entry["priority"] = r.priority;
            entry["action"]   = (r.action == FilterAction::Allow) ? "allow" :
                                (r.action == FilterAction::LogOnly) ? "log" : "block";
            if (r.remotePort)      entry["remotePort"]   = r.remotePort;
            if (r.domainPattern)   entry["domain"]       = *r.domainPattern;
            if (r.processPattern)  entry["processName"]  = Utils::StringUtils::ToNarrow(*r.processPattern);
            entry["hitCount"] = r.hitCount.load(std::memory_order_relaxed);
            j.push_back(entry);
        }
    }
    std::ofstream file(filePath);
    if (!file.is_open()) {
        Utils::Logger::Error("NetworkTrafficFilter: Cannot write rules file: {}",
            Utils::StringUtils::ToNarrow(filePath));
        return false;
    }
    file << j.dump(2);
    return file.good();
}

// ============================================================================
// DNS MONITORING
// ============================================================================

FilterAction NetworkTrafficFilter::OnDNSQuery(const DNSQueryEvent& query) {
    m_impl->m_statDnsQueries.fetch_add(1, std::memory_order_relaxed);

    // Detect DGA
    bool blocked = false;
    FilterAction action = FilterAction::Allow;

    if (m_impl->m_config.detectDGA && IsDGADomain(query.domain)) {
        m_impl->m_statDgaDetected.fetch_add(1, std::memory_order_relaxed);
        action = m_impl->m_config.maliciousDomainAction;
        if (action == FilterAction::Block)
            m_impl->m_statDnsBlocked.fetch_add(1, std::memory_order_relaxed);
    }

    // Domain blocklist check
    if (action != FilterAction::Block) {
        std::shared_lock lock(m_impl->m_blocklistMutex);
        std::string lower = query.domain;
        for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        if (m_impl->m_blockedDomains.count(lower)) {
            action = FilterAction::Block;
            m_impl->m_statDnsBlocked.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Invoke DNS callbacks (outside any lock)
    {
        std::vector<DNSCallback> callbacks;
        {
            std::shared_lock cbLock(m_impl->m_callbackMutex);
            callbacks.reserve(m_impl->m_dnsCallbacks.size());
            for (const auto& [id, cb] : m_impl->m_dnsCallbacks)
                callbacks.push_back(cb);
        }
        for (const auto& cb : callbacks) {
            try {
                if (cb(query) == FilterAction::Block) action = FilterAction::Block;
            } catch (...) {}
        }
    }

    // Compute blocked status AFTER callbacks have had a chance to override verdict
    blocked = (action == FilterAction::Block);

    // Store in DNS history
    DNSQueryEvent stored = query;
    stored.blocked = blocked;
    stored.isDGA   = (m_impl->m_config.detectDGA && IsDGADomain(query.domain));
    {
        std::unique_lock lock(m_impl->m_dnsMutex);
        if (m_impl->m_recentDNS.size() >= NetworkFilterConstants::MAX_CONNECTION_HISTORY)
            m_impl->m_recentDNS.pop_front();
        m_impl->m_recentDNS.push_back(stored);
    }

    return action;
}

std::vector<DNSQueryEvent> NetworkTrafficFilter::GetProcessDNSQueries(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_dnsMutex);
    std::vector<DNSQueryEvent> result;
    for (const auto& q : m_impl->m_recentDNS)
        if (q.processId == pid) result.push_back(q);
    return result;
}

std::vector<DNSQueryEvent> NetworkTrafficFilter::GetRecentDNSQueries(size_t count) const {
    std::shared_lock lock(m_impl->m_dnsMutex);
    const size_t n = std::min(count, m_impl->m_recentDNS.size());
    return std::vector<DNSQueryEvent>(
        m_impl->m_recentDNS.end() - static_cast<std::ptrdiff_t>(n),
        m_impl->m_recentDNS.end());
}

// ============================================================================
// DETECTION
// ============================================================================

BeaconAnalysis NetworkTrafficFilter::AnalyzeBeaconPattern(uint32_t pid, const NetworkEndpoint& remote) {
    return m_impl->AnalyzeBeacon(pid, remote);
}

bool NetworkTrafficFilter::IsDGADomain(const std::string& domain) const {
    if (domain.empty()) return false;
    // Extract the registrable part (everything before the last two labels)
    std::string host = domain;
    // Strip trailing dot
    if (!host.empty() && host.back() == '.') host.pop_back();
    // Get subdomain label (before first dot for simple analysis)
    const size_t dot = host.find('.');
    const std::string label = (dot != std::string::npos) ? host.substr(0, dot) : host;
    if (label.size() < 6) return false; // too short to be DGA

    const double entropy = CalculateDomainEntropy(label);
    if (entropy < m_impl->m_config.dgaEntropyThreshold) return false;

    // Consonant ratio heuristic: DGA domains tend to have high consonant density
    static constexpr std::string_view kVowels = "aeiouAEIOU";
    size_t consonants = 0;
    size_t alphaCount = 0;
    for (char c : label) {
        if (::isalpha(static_cast<unsigned char>(c))) {
            ++alphaCount;
            if (kVowels.find(c) == std::string_view::npos) ++consonants;
        }
    }
    if (alphaCount == 0) return false;
    const double consonantRatio = static_cast<double>(consonants) / static_cast<double>(alphaCount);

    // High entropy AND high consonant ratio = likely DGA
    return (entropy >= m_impl->m_config.dgaEntropyThreshold && consonantRatio > 0.70);
}

double NetworkTrafficFilter::CalculateDomainEntropy(const std::string& domain) const {
    return CalculateShannonEntropy(domain);
}

bool NetworkTrafficFilter::CheckExfiltration(uint32_t pid) {
    // Compute total outbound bytes for this PID across all connections
    uint64_t totalOut = 0;
    {
        std::shared_lock lock(m_impl->m_connectionMutex);
        for (const auto& [id, conn] : m_impl->m_connections) {
            if (conn.processId == pid) totalOut += conn.bytesSent;
        }
    }

    if (totalOut < m_impl->m_config.largeTransferThreshold) return false;

    m_impl->m_statExfiltrationDetected.fetch_add(1, std::memory_order_relaxed);
    Utils::Logger::Warn("NetworkTrafficFilter: Potential exfiltration by PID {} ({} bytes out).", pid, totalOut);

    // Invoke exfiltration callbacks
    std::vector<ExfiltrationCallback> callbacks;
    {
        std::shared_lock cbLock(m_impl->m_callbackMutex);
        callbacks.reserve(m_impl->m_exfilCallbacks.size());
        for (const auto& [id, cb] : m_impl->m_exfilCallbacks)
            callbacks.push_back(cb);
    }

    bool block = (m_impl->m_config.exfiltrationAction == FilterAction::Block);
    for (const auto& cb : callbacks) {
        try {
            NetworkEndpoint dummy{};
            if (cb(pid, dummy, totalOut) == FilterAction::Block) block = true;
        } catch (...) {}
    }

    return block;
}

// ============================================================================
// QUERY METHODS
// ============================================================================

std::optional<NetworkConnection> NetworkTrafficFilter::GetConnection(uint64_t connectionId) const {
    std::shared_lock lock(m_impl->m_connectionMutex);
    auto it = m_impl->m_connections.find(connectionId);
    if (it == m_impl->m_connections.end()) return std::nullopt;
    return it->second;
}

std::vector<NetworkConnection> NetworkTrafficFilter::GetProcessConnections(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_connectionMutex);
    std::vector<NetworkConnection> result;
    for (const auto& [id, conn] : m_impl->m_connections)
        if (conn.processId == pid) result.push_back(conn);
    return result;
}

std::vector<NetworkConnection> NetworkTrafficFilter::GetActiveConnections() const {
    std::shared_lock lock(m_impl->m_connectionMutex);
    std::vector<NetworkConnection> result;
    result.reserve(m_impl->m_connections.size());
    for (const auto& [id, conn] : m_impl->m_connections)
        result.push_back(conn);
    return result;
}

std::vector<NetworkConnection> NetworkTrafficFilter::GetConnectionHistory(size_t count) const {
    std::shared_lock lock(m_impl->m_historyMutex);
    const size_t n = std::min(count, m_impl->m_connectionHistory.size());
    return std::vector<NetworkConnection>(
        m_impl->m_connectionHistory.end() - static_cast<std::ptrdiff_t>(n),
        m_impl->m_connectionHistory.end());
}

std::vector<NetworkConnection> NetworkTrafficFilter::GetConnectionsToIP(const IPAddress& ip) const {
    std::shared_lock lock(m_impl->m_connectionMutex);
    std::vector<NetworkConnection> result;
    for (const auto& [id, conn] : m_impl->m_connections)
        if (conn.tuple.remote.address == ip) result.push_back(conn);
    return result;
}

std::vector<NetworkEvent> NetworkTrafficFilter::GetRecentEvents(size_t count) const {
    std::shared_lock lock(m_impl->m_eventMutex);
    const size_t n = std::min(count, m_impl->m_eventHistory.size());
    return std::vector<NetworkEvent>(
        m_impl->m_eventHistory.end() - static_cast<std::ptrdiff_t>(n),
        m_impl->m_eventHistory.end());
}

// ============================================================================
// STATISTICS
// ============================================================================

NetworkFilterStats NetworkTrafficFilter::GetStats() const {
    NetworkFilterStats snap;
    snap.totalConnections      = m_impl->m_statTotalConnections.load(std::memory_order_relaxed);
    snap.connectionsBlocked    = m_impl->m_statConnectionsBlocked.load(std::memory_order_relaxed);
    snap.connectionsAllowed    = m_impl->m_statConnectionsAllowed.load(std::memory_order_relaxed);
    snap.connectionsTerminated = m_impl->m_statConnectionsTerminated.load(std::memory_order_relaxed);
    snap.bytesOutbound         = m_impl->m_statBytesOutbound.load(std::memory_order_relaxed);
    snap.bytesInbound          = m_impl->m_statBytesInbound.load(std::memory_order_relaxed);
    snap.dnsQueries            = m_impl->m_statDnsQueries.load(std::memory_order_relaxed);
    snap.dnsBlocked            = m_impl->m_statDnsBlocked.load(std::memory_order_relaxed);
    snap.c2Detected            = m_impl->m_statC2Detected.load(std::memory_order_relaxed);
    snap.dgaDetected           = m_impl->m_statDgaDetected.load(std::memory_order_relaxed);
    snap.exfiltrationDetected  = m_impl->m_statExfiltrationDetected.load(std::memory_order_relaxed);
    snap.deepInspections       = m_impl->m_statDeepInspections.load(std::memory_order_relaxed);
    snap.rulesEvaluated        = m_impl->m_statRulesEvaluated.load(std::memory_order_relaxed);
    snap.activeConnections     = m_impl->m_statActiveConnections.load(std::memory_order_relaxed);
    return snap;
}

void NetworkTrafficFilter::ResetStats() {
    m_impl->m_statTotalConnections.store(0, std::memory_order_relaxed);
    m_impl->m_statConnectionsBlocked.store(0, std::memory_order_relaxed);
    m_impl->m_statConnectionsAllowed.store(0, std::memory_order_relaxed);
    m_impl->m_statConnectionsTerminated.store(0, std::memory_order_relaxed);
    m_impl->m_statBytesOutbound.store(0, std::memory_order_relaxed);
    m_impl->m_statBytesInbound.store(0, std::memory_order_relaxed);
    m_impl->m_statDnsQueries.store(0, std::memory_order_relaxed);
    m_impl->m_statDnsBlocked.store(0, std::memory_order_relaxed);
    m_impl->m_statC2Detected.store(0, std::memory_order_relaxed);
    m_impl->m_statDgaDetected.store(0, std::memory_order_relaxed);
    m_impl->m_statExfiltrationDetected.store(0, std::memory_order_relaxed);
    m_impl->m_statDeepInspections.store(0, std::memory_order_relaxed);
    m_impl->m_statRulesEvaluated.store(0, std::memory_order_relaxed);
    // Keep activeConnections as-is (reflects live state)
}

std::pair<uint64_t, uint64_t> NetworkTrafficFilter::GetProcessBandwidth(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_connectionMutex);
    uint64_t sent = 0, received = 0;
    for (const auto& [id, conn] : m_impl->m_connections) {
        if (conn.processId == pid) {
            sent     += conn.bytesSent;
            received += conn.bytesReceived;
        }
    }
    return { sent, received };
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t NetworkTrafficFilter::RegisterConnectionCallback(ConnectionCallback callback) {
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_connectionCallbacks[id] = std::move(callback);
    return id;
}

bool NetworkTrafficFilter::UnregisterConnectionCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_connectionCallbacks.erase(callbackId) > 0;
}

uint64_t NetworkTrafficFilter::RegisterEventCallback(NetworkEventCallback callback) {
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_eventCallbacks[id] = std::move(callback);
    return id;
}

bool NetworkTrafficFilter::UnregisterEventCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_eventCallbacks.erase(callbackId) > 0;
}

uint64_t NetworkTrafficFilter::RegisterDNSCallback(DNSCallback callback) {
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_dnsCallbacks[id] = std::move(callback);
    return id;
}

bool NetworkTrafficFilter::UnregisterDNSCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_dnsCallbacks.erase(callbackId) > 0;
}

uint64_t NetworkTrafficFilter::RegisterC2Callback(C2DetectionCallback callback) {
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_c2Callbacks[id] = std::move(callback);
    return id;
}

bool NetworkTrafficFilter::UnregisterC2Callback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_c2Callbacks.erase(callbackId) > 0;
}

uint64_t NetworkTrafficFilter::RegisterExfiltrationCallback(ExfiltrationCallback callback) {
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_exfilCallbacks[id] = std::move(callback);
    return id;
}

bool NetworkTrafficFilter::UnregisterExfiltrationCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    return m_impl->m_exfilCallbacks.erase(callbackId) > 0;
}

// ============================================================================
// INTEGRATION SETTERS
// ============================================================================

void NetworkTrafficFilter::SetThreatIntelIndex(ShadowStrike::ThreatIntel::ThreatIntelIndex* index) {
    m_impl->m_threatIntel = index;
}

void NetworkTrafficFilter::SetPatternIndex(ShadowStrike::PatternStore::PatternIndex* index) {
    m_impl->m_patternIndex = index;
}

// ============================================================================
// IPAddress / NetworkEndpoint / ConnectionTuple FREE FUNCTION IMPLEMENTATIONS
// ============================================================================

IPAddress IPAddress::FromString(const std::string& str) {
    IPAddress addr;
    if (str.empty()) return addr;

    // Try IPv4
    in_addr v4{};
    if (inet_pton(AF_INET, str.c_str(), &v4) == 1) {
        addr.version = IPVersion::IPv4;
        addr.ipv4    = v4.s_addr; // already in network byte order
        return addr;
    }

    // Try IPv6
    in6_addr v6{};
    if (inet_pton(AF_INET6, str.c_str(), &v6) == 1) {
        addr.version = IPVersion::IPv6;
        std::memcpy(addr.ipv6.data(), v6.s6_addr, 16);
        return addr;
    }

    return addr; // Unknown
}

std::string IPAddress::ToString() const {
    if (version == IPVersion::IPv4) {
        in_addr v4{};
        v4.s_addr = ipv4;
        char buf[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &v4, buf, sizeof(buf))) return buf;
    } else if (version == IPVersion::IPv6) {
        in6_addr v6{};
        std::memcpy(v6.s6_addr, ipv6.data(), 16);
        char buf[INET6_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET6, &v6, buf, sizeof(buf))) return buf;
    }
    return {};
}

bool IPAddress::IsPrivate() const noexcept {
    if (version == IPVersion::IPv4) {
        const uint32_t h = ntohl(ipv4);
        return ((h & 0xFF000000u) == 0x0A000000u) ||  // 10.0.0.0/8
               ((h & 0xFFF00000u) == 0xAC100000u) ||  // 172.16.0.0/12
               ((h & 0xFFFF0000u) == 0xC0A80000u) ||  // 192.168.0.0/16
               ((h & 0xFF000000u) == 0x7F000000u);     // 127.0.0.0/8
    }
    if (version == IPVersion::IPv6) {
        // ::1 (loopback)
        static constexpr std::array<uint8_t, 16> kLoopback6{
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        if (ipv6 == kLoopback6) return true;
        // fc00::/7 (unique local)
        return (ipv6[0] & 0xFE) == 0xFC;
    }
    return false;
}

bool IPAddress::IsLoopback() const noexcept {
    if (version == IPVersion::IPv4)
        return (ntohl(ipv4) & 0xFF000000u) == 0x7F000000u;
    if (version == IPVersion::IPv6) {
        static constexpr std::array<uint8_t, 16> kLoopback6{
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        return ipv6 == kLoopback6;
    }
    return false;
}

bool IPAddress::operator==(const IPAddress& other) const noexcept {
    if (version != other.version) return false;
    if (version == IPVersion::IPv4) return ipv4 == other.ipv4;
    if (version == IPVersion::IPv6) return ipv6 == other.ipv6;
    return true;
}

bool IPAddress::operator!=(const IPAddress& other) const noexcept {
    return !(*this == other);
}

size_t IPAddressHash::operator()(const IPAddress& addr) const noexcept {
    size_t h = std::hash<uint8_t>{}(static_cast<uint8_t>(addr.version));
    if (addr.version == IPVersion::IPv4) {
        h ^= std::hash<uint32_t>{}(addr.ipv4) + 0x9e3779b9u + (h << 6) + (h >> 2);
    } else {
        for (const uint8_t b : addr.ipv6)
            h ^= std::hash<uint8_t>{}(b) + 0x9e3779b9u + (h << 6) + (h >> 2);
    }
    return h;
}

std::string NetworkEndpoint::ToString() const {
    if (address.version == IPVersion::IPv6)
        return "[" + address.ToString() + "]:" + std::to_string(port);
    return address.ToString() + ":" + std::to_string(port);
}

bool NetworkEndpoint::operator==(const NetworkEndpoint& other) const noexcept {
    return address == other.address && port == other.port;
}

uint64_t ConnectionTuple::Hash() const noexcept {
    uint64_t h = static_cast<uint64_t>(protocol);
    auto mix = [&](uint64_t v) {
        h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
    };
    mix(local.address.version == IPVersion::IPv4
            ? static_cast<uint64_t>(local.address.ipv4)
            : std::hash<std::string>{}(local.address.ToString()));
    mix(static_cast<uint64_t>(local.port));
    mix(remote.address.version == IPVersion::IPv4
            ? static_cast<uint64_t>(remote.address.ipv4)
            : std::hash<std::string>{}(remote.address.ToString()));
    mix(static_cast<uint64_t>(remote.port));
    return h;
}

bool ConnectionTuple::operator==(const ConnectionTuple& other) const noexcept {
    return protocol == other.protocol &&
           local    == other.local    &&
           remote   == other.remote;
}

} // namespace RealTime
} // namespace ShadowStrike
