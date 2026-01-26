/**
 * @file NetworkBasedEvasionDetector.cpp
 * @brief Enterprise-grade detection of network-based sandbox/analysis evasion
 *
 * ShadowStrike AntiEvasion - Network-Based Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive detection of malware that uses network
 * characteristics and behaviors to evade sandbox/analysis environments.
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (NetworkUtils, ThreatIntel, Logger)
 */

#include "pch.h"
#include "NetworkBasedEvasionDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <cmath>
#include <execution>
#include <numeric>
#include <queue>
#include <regex>
#include <sstream>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include <wininet.h>
#pragma comment(lib, "wininet.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Get string representation of technique
     */
    [[nodiscard]] const wchar_t* NetworkEvasionTechniqueToString(NetworkEvasionTechnique technique) noexcept {
        switch (technique) {
            // Connectivity checks
        case NetworkEvasionTechnique::CONN_PingKnownDomain:
            return L"Ping to Known Domain";
        case NetworkEvasionTechnique::CONN_HTTPConnectivityCheck:
            return L"HTTP Connectivity Check";
        case NetworkEvasionTechnique::CONN_DNSResolutionCheck:
            return L"DNS Resolution Check";
        case NetworkEvasionTechnique::CONN_NTPTimeCheck:
            return L"NTP Time Synchronization Check";
        case NetworkEvasionTechnique::CONN_InterfaceEnumeration:
            return L"Network Interface Enumeration";
        case NetworkEvasionTechnique::CONN_GatewayCheck:
            return L"Default Gateway Check";
        case NetworkEvasionTechnique::CONN_ReachabilityDetection:
            return L"Internet Reachability Detection";
        case NetworkEvasionTechnique::CONN_ActiveAdapterCheck:
            return L"Active Network Adapter Check";
        case NetworkEvasionTechnique::CONN_BandwidthMeasurement:
            return L"Bandwidth Measurement";
        case NetworkEvasionTechnique::CONN_LatencyCheck:
            return L"Network Latency Check";

            // DNS evasion
        case NetworkEvasionTechnique::DNS_DomainGenerationAlgorithm:
            return L"Domain Generation Algorithm (DGA)";
        case NetworkEvasionTechnique::DNS_FastFlux:
            return L"Fast Flux DNS";
        case NetworkEvasionTechnique::DNS_Tunneling:
            return L"DNS Tunneling";
        case NetworkEvasionTechnique::DNS_SuspiciousTXTQuery:
            return L"Suspicious TXT Record Query";
        case NetworkEvasionTechnique::DNS_ExcessiveLookups:
            return L"Excessive DNS Lookups";
        case NetworkEvasionTechnique::DNS_NXDOMAINPattern:
            return L"NXDOMAIN Pattern Analysis";
        case NetworkEvasionTechnique::DNS_SinkholeDetection:
            return L"DNS Sinkhole Detection";
        case NetworkEvasionTechnique::DNS_PublicResolverCheck:
            return L"Public DNS Resolver Check";
        case NetworkEvasionTechnique::DNS_DoHUsage:
            return L"DNS over HTTPS Usage";
        case NetworkEvasionTechnique::DNS_DoTUsage:
            return L"DNS over TLS Usage";
        case NetworkEvasionTechnique::DNS_RandomSubdomain:
            return L"Random Subdomain Generation";
        case NetworkEvasionTechnique::DNS_CachePoisoning:
            return L"DNS Cache Poisoning Attempt";
        case NetworkEvasionTechnique::DNS_HighEntropyDomain:
            return L"High Entropy Domain Name";
        case NetworkEvasionTechnique::DNS_NewlyRegisteredDomain:
            return L"Newly Registered Domain";
        case NetworkEvasionTechnique::DNS_DomainSquatting:
            return L"Domain Squatting/Typosquatting";

            // Network configuration
        case NetworkEvasionTechnique::NET_ProxyDetection:
            return L"Proxy Detection";
        case NetworkEvasionTechnique::NET_VPNDetection:
            return L"VPN Detection";
        case NetworkEvasionTechnique::NET_TorDetection:
            return L"Tor Detection";
        case NetworkEvasionTechnique::NET_NATDetection:
            return L"NAT Detection";
        case NetworkEvasionTechnique::NET_FirewallEnumeration:
            return L"Firewall Rule Enumeration";
        case NetworkEvasionTechnique::NET_NetworkIsolation:
            return L"Network Isolation Detection";
        case NetworkEvasionTechnique::NET_RestrictedEnvironment:
            return L"Restricted Network Environment";
        case NetworkEvasionTechnique::NET_MACRandomization:
            return L"MAC Address Randomization Check";
        case NetworkEvasionTechnique::NET_MultipleInterfaces:
            return L"Multiple Network Interfaces";
        case NetworkEvasionTechnique::NET_UnusualMTU:
            return L"Unusual MTU Size";

            // Traffic patterns
        case NetworkEvasionTechnique::TRAFFIC_Beaconing:
            return L"Beaconing Behavior";
        case NetworkEvasionTechnique::TRAFFIC_PortScanning:
            return L"Port Scanning Behavior";
        case NetworkEvasionTechnique::TRAFFIC_UnusualProtocol:
            return L"Unusual Protocol Usage";
        case NetworkEvasionTechnique::TRAFFIC_ExcessiveBandwidth:
            return L"Excessive Bandwidth Usage";
        case NetworkEvasionTechnique::TRAFFIC_VolumeAnomaly:
            return L"Traffic Volume Anomaly";
        case NetworkEvasionTechnique::TRAFFIC_RateLimiting:
            return L"Connection Rate Limiting";
        case NetworkEvasionTechnique::TRAFFIC_SuspiciousGeoIP:
            return L"Suspicious Geographic IP";
        case NetworkEvasionTechnique::TRAFFIC_EncryptedNoSNI:
            return L"Encrypted Traffic Without SNI";
        case NetworkEvasionTechnique::TRAFFIC_NonStandardPort:
            return L"Non-Standard Port Usage";
        case NetworkEvasionTechnique::TRAFFIC_Fragmentation:
            return L"Traffic Fragmentation";

            // C2 infrastructure
        case NetworkEvasionTechnique::C2_KnownDomain:
            return L"Known C2 Domain";
        case NetworkEvasionTechnique::C2_KnownIP:
            return L"Known C2 IP Address";
        case NetworkEvasionTechnique::C2_BulletproofHosting:
            return L"Bulletproof Hosting";
        case NetworkEvasionTechnique::C2_CloudProviderAbuse:
            return L"Cloud Provider Abuse";
        case NetworkEvasionTechnique::C2_DynamicDNS:
            return L"Dynamic DNS Usage";
        case NetworkEvasionTechnique::C2_LowReputation:
            return L"Low Domain Reputation";
        case NetworkEvasionTechnique::C2_SelfSignedCert:
            return L"Self-Signed SSL Certificate";
        case NetworkEvasionTechnique::C2_SNIFiltering:
            return L"SNI Filtering Detection";
        case NetworkEvasionTechnique::C2_SuspiciousTLD:
            return L"Suspicious TLD";
        case NetworkEvasionTechnique::C2_IPInURL:
            return L"IP Address in URL";

            // Anti-analysis
        case NetworkEvasionTechnique::ANTI_NetworkCaptureDetection:
            return L"Network Capture Tool Detection";
        case NetworkEvasionTechnique::ANTI_MITMDetection:
            return L"MITM Detection";
        case NetworkEvasionTechnique::ANTI_SSLInspection:
            return L"SSL Inspection Detection";
        case NetworkEvasionTechnique::ANTI_MonitoringTool:
            return L"Traffic Monitoring Tool Detection";
        case NetworkEvasionTechnique::ANTI_SandboxNetwork:
            return L"Sandbox Network Detection";
        case NetworkEvasionTechnique::ANTI_LatencyAnalysis:
            return L"Network Latency Analysis";
        case NetworkEvasionTechnique::ANTI_BandwidthThrottling:
            return L"Bandwidth Throttling Detection";
        case NetworkEvasionTechnique::ANTI_PacketLossAnalysis:
            return L"Packet Loss Rate Analysis";

            // Advanced
        case NetworkEvasionTechnique::ADV_MultiStageC2:
            return L"Multi-Stage C2 Communication";
        case NetworkEvasionTechnique::ADV_DomainFronting:
            return L"Domain Fronting";
        case NetworkEvasionTechnique::ADV_ProtocolTunneling:
            return L"Protocol Tunneling";
        case NetworkEvasionTechnique::ADV_TrafficSteganography:
            return L"Traffic Steganography";
        case NetworkEvasionTechnique::ADV_CovertChannel:
            return L"Covert Channel Usage";
        case NetworkEvasionTechnique::ADV_LOLBINNetwork:
            return L"Living-off-the-Land Network Tools";

        default:
            return L"Unknown Technique";
        }
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class NetworkBasedEvasionDetector::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        /// @brief Thread synchronization
        mutable std::shared_mutex m_mutex;

        /// @brief Initialization state
        std::atomic<bool> m_initialized{ false };

        /// @brief Threat intelligence store
        std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;

        /// @brief Detection callback
        NetworkDetectionCallback m_detectionCallback;

        /// @brief Statistics
        NetworkBasedEvasionDetector::Statistics m_stats;

        /// @brief Result cache
        struct CacheEntry {
            NetworkEvasionResult result;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<uint32_t, CacheEntry> m_resultCache;

        /// @brief DNS query tracking (for rate limiting detection)
        struct DNSTracker {
            std::vector<std::chrono::system_clock::time_point> timestamps;
            std::unordered_map<std::wstring, std::vector<std::wstring>> domainToIPs;
        };
        std::unordered_map<uint32_t, DNSTracker> m_dnsTracking;

        /// @brief Connection tracking (for beaconing detection)
        struct ConnectionTracker {
            std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>> targetTimestamps;
        };
        std::unordered_map<uint32_t, ConnectionTracker> m_connectionTracking;

        /// @brief Known C2 domains/IPs (custom lists)
        std::unordered_set<std::wstring> m_knownC2Domains;
        std::unordered_set<std::wstring> m_knownC2IPs;

        /// @brief Monitoring state
        std::unordered_map<uint32_t, NetworkAnalysisConfig> m_monitoringProcesses;
        std::atomic<bool> m_monitoringActive{ false };

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(NetworkEvasionError* err) noexcept;
        void Shutdown() noexcept;

        // Entropy calculation for domain names
        [[nodiscard]] double CalculateDomainEntropy(std::wstring_view domain) const noexcept;

        // DGA scoring
        [[nodiscard]] double CalculateDGAScore(std::wstring_view domain) const noexcept;

        // Beaconing analysis
        [[nodiscard]] double CalculateBeaconingRegularity(
            const std::vector<std::chrono::system_clock::time_point>& timestamps
        ) const noexcept;

        // Domain validation
        [[nodiscard]] bool IsValidDomain(std::wstring_view domain) const noexcept;

        // IP validation
        [[nodiscard]] bool IsValidIPv4(std::wstring_view ip) const noexcept;

        // Check if domain is in connectivity check list
        [[nodiscard]] bool IsConnectivityCheckDomain(std::wstring_view domain) const noexcept;

        // Check if IP is public DNS resolver
        [[nodiscard]] bool IsPublicDNSResolver(std::wstring_view ip) const noexcept;

        // Parse TLD from domain
        [[nodiscard]] std::wstring GetTLD(std::wstring_view domain) const noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool NetworkBasedEvasionDetector::Impl::Initialize(NetworkEvasionError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            Utils::Logger::Info(L"NetworkBasedEvasionDetector: Initializing...");

            // Initialize Winsock
            WSADATA wsaData;
            const int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (wsaResult != 0) {
                Utils::Logger::Error(L"NetworkBasedEvasionDetector: WSAStartup failed: {}", wsaResult);

                if (err) {
                    err->win32Code = wsaResult;
                    err->message = L"WSAStartup failed";
                }

                m_initialized = false;
                return false;
            }

            // Threat intel is optional (can be set later)

            Utils::Logger::Info(L"NetworkBasedEvasionDetector: Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"NetworkBasedEvasionDetector initialization failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWideString(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            Utils::Logger::Critical(L"NetworkBasedEvasionDetector: Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void NetworkBasedEvasionDetector::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            Utils::Logger::Info(L"NetworkBasedEvasionDetector: Shutting down...");

            // Stop monitoring
            m_monitoringActive = false;
            m_monitoringProcesses.clear();

            // Clear caches
            m_resultCache.clear();
            m_dnsTracking.clear();
            m_connectionTracking.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            // Cleanup Winsock
            WSACleanup();

            Utils::Logger::Info(L"NetworkBasedEvasionDetector: Shutdown complete");
        }
        catch (...) {
            Utils::Logger::Error(L"NetworkBasedEvasionDetector: Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: HELPER METHODS
    // ========================================================================

    double NetworkBasedEvasionDetector::Impl::CalculateDomainEntropy(std::wstring_view domain) const noexcept {
        if (domain.empty()) {
            return 0.0;
        }

        try {
            // Count character frequencies
            std::array<uint64_t, 256> counts{};
            for (wchar_t c : domain) {
                if (c < 256) {
                    counts[c]++;
                }
            }

            // Calculate Shannon entropy
            double entropy = 0.0;
            const double size = static_cast<double>(domain.size());

            for (size_t i = 0; i < 256; ++i) {
                if (counts[i] > 0) {
                    const double p = static_cast<double>(counts[i]) / size;
                    entropy -= p * std::log2(p);
                }
            }

            return entropy;
        }
        catch (...) {
            return 0.0;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateDGAScore(std::wstring_view domain) const noexcept {
        if (domain.empty()) {
            return 0.0;
        }

        try {
            double score = 0.0;

            // Extract domain name without TLD
            size_t lastDot = domain.find_last_of(L'.');
            std::wstring domainName = (lastDot != std::wstring::npos)
                ? std::wstring(domain.substr(0, lastDot))
                : std::wstring(domain);

            // Remove any subdomain parts
            size_t firstDot = domainName.find(L'.');
            if (firstDot != std::wstring::npos) {
                domainName = domainName.substr(firstDot + 1);
            }

            // Factor 1: High entropy (30 points)
            const double entropy = CalculateDomainEntropy(domainName);
            if (entropy >= NetworkEvasionConstants::MIN_DOMAIN_ENTROPY) {
                score += 30.0;
            }

            // Factor 2: Length (20 points)
            // DGA domains are often 8-20 characters
            const size_t len = domainName.length();
            if (len >= 8 && len <= 20) {
                score += 20.0;
            }
            else if (len > 20) {
                score += 10.0;
            }

            // Factor 3: Consonant/vowel ratio (25 points)
            size_t consonants = 0, vowels = 0;
            for (wchar_t c : domainName) {
                c = std::tolower(c);
                if (c == L'a' || c == L'e' || c == L'i' || c == L'o' || c == L'u') {
                    vowels++;
                }
                else if (std::isalpha(c)) {
                    consonants++;
                }
            }

            if (vowels > 0) {
                const double ratio = static_cast<double>(consonants) / vowels;
                // DGA domains tend to have high consonant ratios (3:1 or higher)
                if (ratio >= 3.0) {
                    score += 25.0;
                }
                else if (ratio >= 2.0) {
                    score += 15.0;
                }
            }
            else if (consonants > 0) {
                // No vowels at all is very suspicious
                score += 30.0;
            }

            // Factor 4: No dictionary words (15 points)
            // Simple heuristic: repeated character patterns
            bool hasRepeatedPattern = false;
            for (size_t i = 0; i + 2 < domainName.length(); ++i) {
                if (domainName[i] == domainName[i + 1] && domainName[i] == domainName[i + 2]) {
                    hasRepeatedPattern = true;
                    break;
                }
            }
            if (!hasRepeatedPattern) {
                score += 15.0;
            }

            // Factor 5: Digit presence (10 points)
            bool hasDigits = false;
            for (wchar_t c : domainName) {
                if (std::isdigit(c)) {
                    hasDigits = true;
                    break;
                }
            }
            if (hasDigits) {
                score += 10.0;
            }

            return std::min(score, 100.0);
        }
        catch (...) {
            return 0.0;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateBeaconingRegularity(
        const std::vector<std::chrono::system_clock::time_point>& timestamps
    ) const noexcept {
        if (timestamps.size() < 3) {
            return 0.0; // Not enough data
        }

        try {
            // Calculate intervals between consecutive timestamps
            std::vector<double> intervals;
            intervals.reserve(timestamps.size() - 1);

            for (size_t i = 1; i < timestamps.size(); ++i) {
                const auto duration = timestamps[i] - timestamps[i - 1];
                const double seconds = std::chrono::duration<double>(duration).count();
                intervals.push_back(seconds);
            }

            // Calculate mean interval
            const double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();

            // Calculate variance
            double variance = 0.0;
            for (double interval : intervals) {
                const double diff = interval - mean;
                variance += diff * diff;
            }
            variance /= intervals.size();

            // Calculate coefficient of variation (lower = more regular)
            const double stddev = std::sqrt(variance);
            const double cv = (mean > 0.0) ? (stddev / mean) : 1.0;

            // Convert to regularity score (0-1, higher = more regular)
            // Perfect regularity (cv=0) gives score 1.0
            // High variance (cv>=1) gives score close to 0
            const double regularity = 1.0 / (1.0 + cv);

            return regularity;
        }
        catch (...) {
            return 0.0;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::IsValidDomain(std::wstring_view domain) const noexcept {
        if (domain.empty() || domain.length() > 253) {
            return false;
        }

        // Check for valid characters and structure
        // Simple validation: contains at least one dot, alphanumeric + dash + dot
        bool hasDot = false;
        for (wchar_t c : domain) {
            if (c == L'.') {
                hasDot = true;
            }
            else if (!std::isalnum(c) && c != L'-') {
                return false;
            }
        }

        return hasDot;
    }

    bool NetworkBasedEvasionDetector::Impl::IsValidIPv4(std::wstring_view ip) const noexcept {
        if (ip.empty()) {
            return false;
        }

        try {
            // Simple IPv4 validation: 4 octets separated by dots
            std::wstring ipStr(ip);
            size_t count = 0;
            size_t pos = 0;

            while (pos < ipStr.length()) {
                size_t nextDot = ipStr.find(L'.', pos);
                std::wstring octet = (nextDot != std::wstring::npos)
                    ? ipStr.substr(pos, nextDot - pos)
                    : ipStr.substr(pos);

                if (octet.empty() || octet.length() > 3) {
                    return false;
                }

                int value = std::stoi(octet);
                if (value < 0 || value > 255) {
                    return false;
                }

                count++;
                if (nextDot == std::wstring::npos) {
                    break;
                }
                pos = nextDot + 1;
            }

            return count == 4;
        }
        catch (...) {
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::IsConnectivityCheckDomain(std::wstring_view domain) const noexcept {
        for (const auto& checkDomain : NetworkEvasionConstants::CONNECTIVITY_CHECK_DOMAINS) {
            if (domain.find(checkDomain) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    bool NetworkBasedEvasionDetector::Impl::IsPublicDNSResolver(std::wstring_view ip) const noexcept {
        for (const auto& resolver : NetworkEvasionConstants::PUBLIC_DNS_RESOLVERS) {
            if (ip == resolver) {
                return true;
            }
        }
        return false;
    }

    std::wstring NetworkBasedEvasionDetector::Impl::GetTLD(std::wstring_view domain) const noexcept {
        const size_t lastDot = domain.find_last_of(L'.');
        if (lastDot != std::wstring::npos && lastDot + 1 < domain.length()) {
            return std::wstring(domain.substr(lastDot + 1));
        }
        return L"";
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    NetworkBasedEvasionDetector::NetworkBasedEvasionDetector() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    NetworkBasedEvasionDetector::NetworkBasedEvasionDetector(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_threatIntel = std::move(threatIntel);
    }

    NetworkBasedEvasionDetector::~NetworkBasedEvasionDetector() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    NetworkBasedEvasionDetector::NetworkBasedEvasionDetector(NetworkBasedEvasionDetector&&) noexcept = default;
    NetworkBasedEvasionDetector& NetworkBasedEvasionDetector::operator=(NetworkBasedEvasionDetector&&) noexcept = default;

    bool NetworkBasedEvasionDetector::Initialize(NetworkEvasionError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->win32Code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid detector instance";
            }
            return false;
        }
        return m_impl->Initialize(err);
    }

    void NetworkBasedEvasionDetector::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool NetworkBasedEvasionDetector::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================

    NetworkEvasionResult NetworkBasedEvasionDetector::AnalyzeProcess(
        uint32_t processId,
        const NetworkAnalysisConfig& config,
        NetworkEvasionError* err
    ) noexcept {
        NetworkEvasionResult result;
        result.processId = processId;
        result.config = config;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const auto startTime = std::chrono::high_resolution_clock::now();
            result.analysisStartTime = std::chrono::system_clock::now();

            // Check cache first
            if (HasFlag(config.flags, NetworkAnalysisFlags::EnableCaching)) {
                std::shared_lock lock(m_impl->m_mutex);
                auto it = m_impl->m_resultCache.find(processId);

                if (it != m_impl->m_resultCache.end()) {
                    const auto age = std::chrono::steady_clock::now() - it->second.timestamp;
                    const auto maxAge = std::chrono::seconds(config.cacheTtlSeconds);

                    if (age < maxAge) {
                        m_impl->m_stats.cacheHits++;
                        result = it->second.result;
                        result.fromCache = true;
                        return result;
                    }
                }
                m_impl->m_stats.cacheMisses++;
            }

            // Get process name
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (hProcess) {
                result.processName = Utils::ProcessUtils::GetProcessName(hProcess);
                CloseHandle(hProcess);
            }

            // Perform analysis
            AnalyzeProcessInternal(nullptr, processId, config, result);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            result.analysisDurationMs = duration.count();
            result.analysisEndTime = std::chrono::system_clock::now();
            result.analysisComplete = true;

            m_impl->m_stats.totalAnalyses++;
            m_impl->m_stats.totalAnalysisTimeUs += std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

            if (result.isEvasive) {
                m_impl->m_stats.evasiveProcesses++;
            }

            // Update cache
            if (HasFlag(config.flags, NetworkAnalysisFlags::EnableCaching)) {
                UpdateCache(processId, result);
            }

            return result;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeProcess failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWideString(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            Utils::Logger::Critical(L"AnalyzeProcess: Unknown error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown analysis error";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    NetworkEvasionResult NetworkBasedEvasionDetector::AnalyzeProcess(
        HANDLE hProcess,
        const NetworkAnalysisConfig& config,
        NetworkEvasionError* err
    ) noexcept {
        NetworkEvasionResult result;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const uint32_t processId = GetProcessId(hProcess);
            if (processId == 0) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to get process ID";
                }
                return result;
            }

            return AnalyzeProcess(processId, config, err);
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeProcess (handle) failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Process analysis failed";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    // ========================================================================
    // DOMAIN/URL ANALYSIS
    // ========================================================================

    bool NetworkBasedEvasionDetector::AnalyzeDomain(
        std::wstring_view domain,
        std::vector<NetworkDetectedTechnique>& outDetections,
        NetworkEvasionError* err
    ) noexcept {
        try {
            outDetections.clear();

            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return false;
            }

            if (!m_impl->IsValidDomain(domain)) {
                if (err) {
                    err->win32Code = ERROR_INVALID_PARAMETER;
                    err->message = L"Invalid domain";
                }
                return false;
            }

            // Check if connectivity check domain
            if (m_impl->IsConnectivityCheckDomain(domain)) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::CONN_DNSResolutionCheck);
                detection.confidence = 0.8;
                detection.target = std::wstring(domain);
                detection.description = L"Known connectivity check domain";
                outDetections.push_back(std::move(detection));
            }

            // Check DGA
            double dgaScore = 0.0;
            if (IsDGADomain(domain, dgaScore, err)) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::DNS_DomainGenerationAlgorithm);
                detection.confidence = dgaScore / 100.0;
                detection.target = std::wstring(domain);
                detection.description = L"DGA domain detected";
                detection.technicalDetails = std::format(L"DGA Score: {:.2f}", dgaScore);
                outDetections.push_back(std::move(detection));

                m_impl->m_stats.dgaDetections++;
            }

            // Check high entropy
            const double entropy = m_impl->CalculateDomainEntropy(domain);
            if (entropy >= NetworkEvasionConstants::MIN_DOMAIN_ENTROPY) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::DNS_HighEntropyDomain);
                detection.confidence = 0.7;
                detection.target = std::wstring(domain);
                detection.description = L"High entropy domain name";
                detection.technicalDetails = std::format(L"Entropy: {:.2f}", entropy);
                outDetections.push_back(std::move(detection));
            }

            // Check suspicious TLD
            const auto tld = m_impl->GetTLD(domain);
            const std::vector<std::wstring> suspiciousTLDs = {
                L"tk", L"ml", L"ga", L"cf", L"gq", L"xyz", L"top", L"work", L"click"
            };

            for (const auto& suspiciousTLD : suspiciousTLDs) {
                if (tld == suspiciousTLD) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_SuspiciousTLD);
                    detection.confidence = 0.6;
                    detection.target = std::wstring(domain);
                    detection.description = L"Suspicious TLD: " + tld;
                    outDetections.push_back(std::move(detection));
                    break;
                }
            }

            // Check against threat intel
            if (m_impl->m_threatIntel) {
                // TODO: Query threat intel for domain reputation
            }

            // Check against custom C2 lists
            {
                std::shared_lock lock(m_impl->m_mutex);
                if (m_impl->m_knownC2Domains.find(std::wstring(domain)) != m_impl->m_knownC2Domains.end()) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_KnownDomain);
                    detection.confidence = 1.0;
                    detection.severity = NetworkEvasionSeverity::Critical;
                    detection.target = std::wstring(domain);
                    detection.description = L"Known C2 domain";
                    outDetections.push_back(std::move(detection));

                    m_impl->m_stats.c2Detections++;
                }
            }

            return !outDetections.empty();
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeDomain failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Domain analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::AnalyzeDomains(
        const std::vector<std::wstring>& domains,
        std::vector<NetworkDetectedTechnique>& outDetections,
        NetworkEvasionError* err
    ) noexcept {
        try {
            outDetections.clear();

            for (const auto& domain : domains) {
                std::vector<NetworkDetectedTechnique> domainDetections;
                if (AnalyzeDomain(domain, domainDetections, err)) {
                    outDetections.insert(outDetections.end(),
                        std::make_move_iterator(domainDetections.begin()),
                        std::make_move_iterator(domainDetections.end()));
                }
            }

            return !outDetections.empty();
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"AnalyzeDomains failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Batch domain analysis failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::IsDGADomain(
        std::wstring_view domain,
        double& outScore,
        NetworkEvasionError* err
    ) noexcept {
        try {
            outScore = m_impl->CalculateDGAScore(domain);
            return outScore >= NetworkEvasionConstants::MIN_DGA_SCORE;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"IsDGADomain failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"DGA detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    // ========================================================================
    // NETWORK CHECKS
    // ========================================================================

    bool NetworkBasedEvasionDetector::CheckInternetConnectivity(
        NetworkEvasionError* err
    ) noexcept {
        try {
            // Check using Windows API first
            DWORD flags = 0;
            if (InternetGetConnectedState(&flags, 0)) {
                return true;
            }

            // Try DNS resolution of known domains
            for (const auto& domain : { L"google.com", L"microsoft.com", L"cloudflare.com" }) {
                std::vector<std::wstring> ips;
                if (Utils::NetworkUtils::ResolveDNS(domain, ips)) {
                    return true;
                }
            }

            return false;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"CheckInternetConnectivity failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Connectivity check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::DetectProxy(
        std::wstring& outProxyAddress,
        NetworkEvasionError* err
    ) noexcept {
        try {
            // Check environment variables
            const std::vector<std::wstring> proxyVars = {
                L"HTTP_PROXY", L"HTTPS_PROXY", L"http_proxy", L"https_proxy"
            };

            for (const auto& varName : proxyVars) {
                wchar_t buffer[1024] = {};
                const DWORD result = GetEnvironmentVariableW(varName.c_str(), buffer, _countof(buffer));

                if (result > 0 && result < _countof(buffer)) {
                    outProxyAddress = buffer;
                    return true;
                }
            }

            // Check Internet Explorer proxy settings
            INTERNET_PROXY_INFO proxyInfo = {};
            DWORD proxyInfoSize = sizeof(proxyInfo);

            if (InternetQueryOptionW(nullptr, INTERNET_OPTION_PROXY, &proxyInfo, &proxyInfoSize)) {
                if (proxyInfo.lpszProxy && proxyInfo.lpszProxy[0] != L'\0') {
                    outProxyAddress = proxyInfo.lpszProxy;
                    return true;
                }
            }

            return false;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"DetectProxy failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Proxy detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::DetectVPN(
        std::wstring& outVPNAdapter,
        NetworkEvasionError* err
    ) noexcept {
        try {
            // Get network adapter information
            ULONG bufferSize = 0;
            GetAdaptersInfo(nullptr, &bufferSize);

            std::vector<uint8_t> buffer(bufferSize);
            auto* pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());

            if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_SUCCESS) {
                auto* pAdapter = pAdapterInfo;

                while (pAdapter) {
                    const std::string desc(pAdapter->Description);

                    // Common VPN adapter keywords
                    const std::vector<std::string> vpnKeywords = {
                        "VPN", "TAP", "TUN", "Virtual", "OpenVPN", "WireGuard",
                        "NordVPN", "ExpressVPN", "Cisco AnyConnect"
                    };

                    for (const auto& keyword : vpnKeywords) {
                        if (desc.find(keyword) != std::string::npos) {
                            outVPNAdapter = Utils::StringUtils::ToWideString(desc);
                            return true;
                        }
                    }

                    pAdapter = pAdapter->Next;
                }
            }

            return false;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"DetectVPN failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"VPN detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::DetectTor(
        NetworkEvasionError* err
    ) noexcept {
        try {
            // Check for Tor processes
            const std::vector<std::wstring> torProcesses = {
                L"tor.exe", L"firefox.exe" // Tor Browser uses Firefox
            };

            for (const auto& procName : torProcesses) {
                if (Utils::ProcessUtils::IsProcessRunning(procName)) {
                    // Additional validation: check for SOCKS proxy on port 9050/9150
                    // (Simplified - would need actual port check in production)
                    return true;
                }
            }

            return false;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"DetectTor failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Tor detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::DetectBeaconing(
        const std::vector<std::chrono::system_clock::time_point>& timestamps,
        BeaconingInfo& outInfo,
        NetworkEvasionError* err
    ) noexcept {
        try {
            outInfo = BeaconingInfo{};

            if (timestamps.size() < 3) {
                return false; // Not enough data
            }

            outInfo.timestamps = timestamps;
            outInfo.beaconCount = timestamps.size();

            // Calculate regularity
            outInfo.regularityScore = m_impl->CalculateBeaconingRegularity(timestamps);

            // Calculate average interval
            std::vector<double> intervals;
            for (size_t i = 1; i < timestamps.size(); ++i) {
                const auto duration = timestamps[i] - timestamps[i - 1];
                intervals.push_back(std::chrono::duration<double>(duration).count());
            }

            outInfo.averageIntervalSec = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();

            // Calculate variance
            double variance = 0.0;
            for (double interval : intervals) {
                const double diff = interval - outInfo.averageIntervalSec;
                variance += diff * diff;
            }
            outInfo.intervalVariance = variance / intervals.size();

            // Determine if beaconing
            outInfo.isBeaconing = (outInfo.regularityScore >= NetworkEvasionConstants::MIN_BEACONING_REGULARITY);

            if (outInfo.isBeaconing) {
                m_impl->m_stats.beaconingDetections++;
            }

            return outInfo.isBeaconing;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"DetectBeaconing failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Beaconing detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::DetectFastFlux(
        std::wstring_view domain,
        FastFluxInfo& outInfo,
        NetworkEvasionError* err
    ) noexcept {
        try {
            outInfo = FastFluxInfo{};
            outInfo.domain = domain;

            // Resolve domain multiple times to detect IP changes
            const size_t numQueries = 5;
            std::unordered_set<std::wstring> uniqueIPs;

            for (size_t i = 0; i < numQueries; ++i) {
                std::vector<std::wstring> ips;
                if (Utils::NetworkUtils::ResolveDNS(domain, ips)) {
                    for (const auto& ip : ips) {
                        if (uniqueIPs.insert(ip).second) {
                            outInfo.observedIPs.push_back(ip);
                            outInfo.changeTimestamps.push_back(std::chrono::system_clock::now());
                        }
                    }
                }

                // Small delay between queries
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            outInfo.ipChangeCount = outInfo.observedIPs.size();

            // Fast flux: many different IPs for same domain
            outInfo.isFastFlux = (outInfo.ipChangeCount >= NetworkEvasionConstants::MIN_FAST_FLUX_IP_CHANGES);

            return outInfo.isFastFlux;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"DetectFastFlux failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Fast flux detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    bool NetworkBasedEvasionDetector::StartMonitoring(
        uint32_t processId,
        const NetworkAnalysisConfig& config,
        NetworkEvasionError* err
    ) noexcept {
        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return false;
            }

            std::unique_lock lock(m_impl->m_mutex);

            m_impl->m_monitoringProcesses[processId] = config;
            m_impl->m_monitoringActive = true;

            Utils::Logger::Info(L"NetworkBasedEvasionDetector: Started monitoring process {}", processId);
            return true;
        }
        catch (const std::exception& e) {
            Utils::Logger::Error(L"StartMonitoring failed: {}",
                Utils::StringUtils::ToWideString(e.what()));

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Failed to start monitoring";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    void NetworkBasedEvasionDetector::StopMonitoring(uint32_t processId) noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_monitoringProcesses.erase(processId);

            Utils::Logger::Info(L"NetworkBasedEvasionDetector: Stopped monitoring process {}", processId);
        }
        catch (...) {
            Utils::Logger::Error(L"StopMonitoring: Exception");
        }
    }

    void NetworkBasedEvasionDetector::StopAllMonitoring() noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_monitoringProcesses.clear();
            m_impl->m_monitoringActive = false;

            Utils::Logger::Info(L"NetworkBasedEvasionDetector: Stopped all monitoring");
        }
        catch (...) {
            Utils::Logger::Error(L"StopAllMonitoring: Exception");
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void NetworkBasedEvasionDetector::SetDetectionCallback(NetworkDetectionCallback callback) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = std::move(callback);
    }

    void NetworkBasedEvasionDetector::ClearDetectionCallback() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = nullptr;
    }

    // ========================================================================
    // CACHING
    // ========================================================================

    std::optional<NetworkEvasionResult> NetworkBasedEvasionDetector::GetCachedResult(
        uint32_t processId
    ) const noexcept {
        std::shared_lock lock(m_impl->m_mutex);

        auto it = m_impl->m_resultCache.find(processId);
        if (it != m_impl->m_resultCache.end()) {
            return it->second.result;
        }

        return std::nullopt;
    }

    void NetworkBasedEvasionDetector::InvalidateCache(uint32_t processId) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.erase(processId);
    }

    void NetworkBasedEvasionDetector::ClearCache() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.clear();
    }

    size_t NetworkBasedEvasionDetector::GetCacheSize() const noexcept {
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->m_resultCache.size();
    }

    void NetworkBasedEvasionDetector::UpdateCache(
        uint32_t processId,
        const NetworkEvasionResult& result
    ) noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);

            // Enforce cache size limit
            if (m_impl->m_resultCache.size() >= NetworkEvasionConstants::MAX_CACHE_ENTRIES) {
                // Remove oldest entry
                auto oldest = m_impl->m_resultCache.begin();
                for (auto it = m_impl->m_resultCache.begin(); it != m_impl->m_resultCache.end(); ++it) {
                    if (it->second.timestamp < oldest->second.timestamp) {
                        oldest = it;
                    }
                }
                m_impl->m_resultCache.erase(oldest);
            }

            Impl::CacheEntry entry;
            entry.result = result;
            entry.timestamp = std::chrono::steady_clock::now();

            m_impl->m_resultCache[processId] = std::move(entry);
        }
        catch (...) {
            // Cache update failure is non-fatal
        }
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void NetworkBasedEvasionDetector::SetThreatIntelStore(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
    ) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_threatIntel = std::move(threatIntel);
    }

    void NetworkBasedEvasionDetector::AddKnownC2Domain(std::wstring_view domain) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_knownC2Domains.insert(std::wstring(domain));
    }

    void NetworkBasedEvasionDetector::AddKnownC2IP(std::wstring_view ip) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_knownC2IPs.insert(std::wstring(ip));
    }

    void NetworkBasedEvasionDetector::ClearCustomLists() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_knownC2Domains.clear();
        m_impl->m_knownC2IPs.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const NetworkBasedEvasionDetector::Statistics& NetworkBasedEvasionDetector::GetStatistics() const noexcept {
        return m_impl->m_stats;
    }

    void NetworkBasedEvasionDetector::ResetStatistics() noexcept {
        m_impl->m_stats.Reset();
    }

    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    void NetworkBasedEvasionDetector::AnalyzeProcessInternal(
        HANDLE hProcess,
        uint32_t processId,
        const NetworkAnalysisConfig& config,
        NetworkEvasionResult& result
    ) noexcept {
        // Analyze network configuration
        if (HasFlag(config.flags, NetworkAnalysisFlags::ScanNetworkConfig)) {
            CheckNetworkConfiguration(result);
        }

        // Analyze connectivity checks
        if (HasFlag(config.flags, NetworkAnalysisFlags::ScanConnectivity)) {
            CheckConnectivity(result);
        }

        // Analyze DNS activity
        if (HasFlag(config.flags, NetworkAnalysisFlags::ScanDNS)) {
            std::shared_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_dnsTracking.find(processId);
            if (it != m_impl->m_dnsTracking.end()) {
                CheckDNSEvasion(it->second, result);
            }
        }

        // Analyze traffic patterns
        if (HasFlag(config.flags, NetworkAnalysisFlags::ScanTrafficPatterns)) {
            std::shared_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_connectionTracking.find(processId);
            if (it != m_impl->m_connectionTracking.end()) {
                CheckTrafficPatterns(it->second, result);
            }
        }

        // Analyze beaconing
        if (HasFlag(config.flags, NetworkAnalysisFlags::ScanBeaconing)) {
            std::shared_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_connectionTracking.find(processId);
            if (it != m_impl->m_connectionTracking.end()) {
                CheckBeaconing(it->second, result);
            }
        }

        // Calculate evasion score
        CalculateEvasionScore(result);
    }

    void NetworkBasedEvasionDetector::CheckConnectivity(
        NetworkEvasionResult& result
    ) noexcept {
        try {
            // Check if internet connectivity exists
            result.networkConfig.hasInternetConnectivity = CheckInternetConnectivity(nullptr);

            if (!result.networkConfig.hasInternetConnectivity) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::CONN_ReachabilityDetection);
                detection.confidence = 0.7;
                detection.description = L"No internet connectivity detected";
                AddDetection(result, std::move(detection));
            }
        }
        catch (...) {
            Utils::Logger::Error(L"CheckConnectivity: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckDNSEvasion(
        const Impl::DNSTracker& tracker,
        NetworkEvasionResult& result
    ) noexcept {
        try {
            result.totalDNSQueries = static_cast<uint32_t>(tracker.timestamps.size());
            m_impl->m_stats.totalDNSQueries += result.totalDNSQueries;

            // Check for excessive DNS queries
            if (!tracker.timestamps.empty()) {
                const auto now = std::chrono::system_clock::now();
                const auto oneMinuteAgo = now - std::chrono::minutes(1);

                size_t recentQueries = 0;
                for (const auto& ts : tracker.timestamps) {
                    if (ts >= oneMinuteAgo) {
                        recentQueries++;
                    }
                }

                if (recentQueries > NetworkEvasionConstants::MAX_NORMAL_DNS_QUERIES) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::DNS_ExcessiveLookups);
                    detection.confidence = 0.8;
                    detection.description = L"Excessive DNS queries";
                    detection.technicalDetails = std::format(L"Queries per minute: {}", recentQueries);
                    AddDetection(result, std::move(detection));
                }
            }

            // Check each domain for DGA, fast flux, etc.
            for (const auto& [domain, ips] : tracker.domainToIPs) {
                std::vector<NetworkDetectedTechnique> domainDetections;
                AnalyzeDomain(domain, domainDetections, nullptr);

                for (auto& detection : domainDetections) {
                    AddDetection(result, std::move(detection));
                }

                // Check for fast flux (many IPs for one domain)
                if (ips.size() >= NetworkEvasionConstants::MIN_FAST_FLUX_IP_CHANGES) {
                    FastFluxInfo ffInfo;
                    ffInfo.domain = domain;
                    ffInfo.observedIPs = ips;
                    ffInfo.ipChangeCount = ips.size();
                    ffInfo.isFastFlux = true;

                    result.fastFluxDomains.push_back(ffInfo);

                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::DNS_FastFlux);
                    detection.confidence = 0.9;
                    detection.target = domain;
                    detection.description = L"Fast flux DNS detected";
                    detection.technicalDetails = std::format(L"IP count: {}", ips.size());
                    AddDetection(result, std::move(detection));
                }
            }
        }
        catch (...) {
            Utils::Logger::Error(L"CheckDNSEvasion: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckNetworkConfiguration(
        NetworkEvasionResult& result
    ) noexcept {
        try {
            // Check for proxy
            std::wstring proxyAddr;
            if (DetectProxy(proxyAddr, nullptr)) {
                result.networkConfig.hasProxy = true;
                result.networkConfig.proxyAddress = proxyAddr;

                NetworkDetectedTechnique detection(NetworkEvasionTechnique::NET_ProxyDetection);
                detection.confidence = 0.6;
                detection.description = L"Proxy detected";
                detection.detectedValue = proxyAddr;
                AddDetection(result, std::move(detection));
            }

            // Check for VPN
            std::wstring vpnAdapter;
            if (DetectVPN(vpnAdapter, nullptr)) {
                result.networkConfig.hasVPN = true;
                result.networkConfig.vpnAdapter = vpnAdapter;

                NetworkDetectedTechnique detection(NetworkEvasionTechnique::NET_VPNDetection);
                detection.confidence = 0.7;
                detection.description = L"VPN detected";
                detection.detectedValue = vpnAdapter;
                AddDetection(result, std::move(detection));
            }

            // Check for Tor
            if (DetectTor(nullptr)) {
                result.networkConfig.hasTor = true;

                NetworkDetectedTechnique detection(NetworkEvasionTechnique::NET_TorDetection);
                detection.confidence = 0.8;
                detection.description = L"Tor detected";
                AddDetection(result, std::move(detection));
            }

            result.networkConfig.valid = true;
        }
        catch (...) {
            Utils::Logger::Error(L"CheckNetworkConfiguration: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckTrafficPatterns(
        const Impl::ConnectionTracker& tracker,
        NetworkEvasionResult& result
    ) noexcept {
        try {
            result.totalConnections = 0;

            for (const auto& [target, timestamps] : tracker.targetTimestamps) {
                result.totalConnections += static_cast<uint32_t>(timestamps.size());
            }

            m_impl->m_stats.totalHTTPRequests += result.totalConnections;
        }
        catch (...) {
            Utils::Logger::Error(L"CheckTrafficPatterns: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckBeaconing(
        const Impl::ConnectionTracker& tracker,
        NetworkEvasionResult& result
    ) noexcept {
        try {
            for (const auto& [target, timestamps] : tracker.targetTimestamps) {
                if (timestamps.size() >= 3) {
                    BeaconingInfo beaconInfo;
                    if (DetectBeaconing(timestamps, beaconInfo, nullptr)) {
                        beaconInfo.target = target;
                        result.beacons.push_back(beaconInfo);

                        NetworkDetectedTechnique detection(NetworkEvasionTechnique::TRAFFIC_Beaconing);
                        detection.confidence = beaconInfo.regularityScore;
                        detection.severity = NetworkEvasionSeverity::Critical;
                        detection.target = target;
                        detection.description = L"Beaconing behavior detected";
                        detection.technicalDetails = std::format(
                            L"Regularity: {:.2f}, Avg interval: {:.2f}s",
                            beaconInfo.regularityScore,
                            beaconInfo.averageIntervalSec
                        );
                        AddDetection(result, std::move(detection));
                    }
                }
            }
        }
        catch (...) {
            Utils::Logger::Error(L"CheckBeaconing: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CalculateEvasionScore(NetworkEvasionResult& result) noexcept {
        double score = 0.0;
        NetworkEvasionSeverity maxSev = NetworkEvasionSeverity::Low;

        for (const auto& detection : result.detectedTechniques) {
            // Weight by category
            double categoryWeight = detection.weight;

            // Weight by severity
            double severityMultiplier = 1.0;
            switch (detection.severity) {
            case NetworkEvasionSeverity::Low: severityMultiplier = 1.0; break;
            case NetworkEvasionSeverity::Medium: severityMultiplier = 2.5; break;
            case NetworkEvasionSeverity::High: severityMultiplier = 5.0; break;
            case NetworkEvasionSeverity::Critical: severityMultiplier = 10.0; break;
            }

            score += (categoryWeight * severityMultiplier * detection.confidence);

            if (detection.severity > maxSev) {
                maxSev = detection.severity;
            }
        }

        result.evasionScore = std::min(score, 100.0);
        result.maxSeverity = maxSev;
        result.isEvasive = (score >= 50.0); // Threshold for evasive behavior
    }

    void NetworkBasedEvasionDetector::AddDetection(
        NetworkEvasionResult& result,
        NetworkDetectedTechnique detection
    ) noexcept {
        // Set category bit
        const auto catIdx = static_cast<uint32_t>(detection.category);
        if (catIdx < 32) {
            result.detectedCategories |= (1u << catIdx);
            m_impl->m_stats.categoryDetections[catIdx % 16]++;
        }

        result.totalDetections++;
        m_impl->m_stats.totalDetections++;

        // Invoke callback if set
        if (m_impl->m_detectionCallback) {
            try {
                m_impl->m_detectionCallback(result.processId, detection);
            }
            catch (...) {
                // Swallow callback exceptions
            }
        }

        result.detectedTechniques.push_back(std::move(detection));
    }

} // namespace ShadowStrike::AntiEvasion
