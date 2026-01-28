/**
 * @file NetworkBasedEvasionDetector.hpp
 * @brief Enterprise-grade detection of network-based sandbox/analysis evasion
 *
 * ShadowStrike AntiEvasion - Network-Based Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This module detects malware that uses network characteristics and behaviors
 * to evade sandbox/analysis environments. Modern malware checks network
 * connectivity, DNS responses, gateway configurations, and traffic patterns
 * before executing malicious payloads.
 *
 * DETECTION CAPABILITIES:
 *
 * INTERNET CONNECTIVITY CHECKS:
 * - Ping to known domains (google.com, microsoft.com, etc.)
 * - HTTP/HTTPS connectivity probes
 * - DNS resolution checks
 * - NTP time synchronization checks
 * - Network interface enumeration
 * - Default gateway validation
 * - Internet reachability detection
 *
 * DNS-BASED EVASION:
 * - Domain Generation Algorithms (DGA) detection
 * - Fast flux detection (rapidly changing IPs)
 * - DNS tunneling detection
 * - Suspicious TXT record queries
 * - Excessive DNS lookups
 * - Non-existent domain (NXDOMAIN) pattern analysis
 * - DNS sinkhole detection
 * - Public DNS resolver checks (8.8.8.8, 1.1.1.1, etc.)
 *
 * NETWORK CONFIGURATION CHECKS:
 * - Proxy detection (HTTP_PROXY, HTTPS_PROXY env vars)
 * - VPN detection (TAP adapters, VPN processes)
 * - Tor detection (Tor processes, SOCKS proxies)
 * - NAT detection
 * - Firewall rule enumeration
 * - Network isolation detection
 * - Restricted network environment detection
 *
 * TRAFFIC PATTERN ANALYSIS:
 * - Beaconing detection (periodic C2 communication)
 * - Port scanning behavior
 * - Unusual protocol usage
 * - Excessive bandwidth usage
 * - Traffic volume anomalies
 * - Connection rate limiting checks
 * - Geographic IP validation
 *
 * C2 INFRASTRUCTURE DETECTION:
 * - Known C2 domain/IP blacklists
 * - Bulletproof hosting detection
 * - Cloud provider abuse detection
 * - Dynamic DNS usage
 * - Domain reputation checks
 * - SSL/TLS certificate validation
 * - SNI-based filtering detection
 *
 * ANTI-ANALYSIS TECHNIQUES:
 * - Network latency checks (sandbox detection)
 * - Bandwidth throttling detection
 * - Network capture tool detection (Wireshark, Fiddler, etc.)
 * - Man-in-the-middle (MITM) detection
 * - SSL inspection detection
 * - Network monitoring tool enumeration
 *
 * ============================================================================
 * PERFORMANCE TARGETS
 * ============================================================================
 *
 * - Single check: < 50ms
 * - Full network analysis: < 500ms
 * - DNS query analysis: < 100ms
 * - Traffic pattern analysis: < 200ms
 * - Batch domain check (100 domains): < 2 seconds
 *
 * ============================================================================
 * INTEGRATION POINTS
 * ============================================================================
 *
 * - NetworkUtils - All network operations, DNS queries, HTTP requests
 * - ThreatIntelStore - Known bad domains, IPs, C2 infrastructure
 * - Logger - Comprehensive logging of network activity
 * - StringUtils - Domain/URL parsing and validation
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * - T1071: Application Layer Protocol (C2 over HTTP/DNS)
 * - T1071.001: Web Protocols
 * - T1071.004: DNS
 * - T1090: Proxy
 * - T1090.001: Internal Proxy
 * - T1090.002: External Proxy
 * - T1090.003: Multi-hop Proxy
 * - T1573: Encrypted Channel
 * - T1008: Fallback Channels
 * - T1568: Dynamic Resolution (DGA, Fast Flux)
 * - T1568.001: Fast Flux DNS
 * - T1568.002: Domain Generation Algorithms
 * - T1205: Traffic Signaling
 *
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>

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
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#endif

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/NetworkUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"

// Forward declarations
namespace ShadowStrike::ThreatIntel {
    class ThreatIntelStore;
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace NetworkEvasionConstants {

            // ========================================================================
            // RESOURCE LIMITS
            // ========================================================================

            /// @brief Maximum domains to check per analysis
            inline constexpr size_t MAX_DOMAINS_PER_ANALYSIS = 1000;

            /// @brief Maximum DNS queries per minute
            inline constexpr size_t MAX_DNS_QUERIES_PER_MINUTE = 100;

            /// @brief Default analysis timeout (milliseconds)
            inline constexpr uint32_t DEFAULT_ANALYSIS_TIMEOUT_MS = 5000;

            /// @brief DNS query timeout (milliseconds)
            inline constexpr uint32_t DNS_QUERY_TIMEOUT_MS = 2000;

            /// @brief HTTP connection timeout (milliseconds)
            inline constexpr uint32_t HTTP_CONNECTION_TIMEOUT_MS = 3000;

            /// @brief Cache entry TTL (seconds)
            inline constexpr uint32_t RESULT_CACHE_TTL_SECONDS = 300;

            /// @brief Maximum cache entries
            inline constexpr size_t MAX_CACHE_ENTRIES = 2048;

            // ========================================================================
            // DETECTION THRESHOLDS
            // ========================================================================

            /// @brief Minimum DGA score for detection (0-100)
            inline constexpr double MIN_DGA_SCORE = 70.0;

            /// @brief Maximum legitimate DNS queries per minute
            inline constexpr size_t MAX_NORMAL_DNS_QUERIES = 50;

            /// @brief Minimum beaconing regularity score (0-1)
            inline constexpr double MIN_BEACONING_REGULARITY = 0.8;

            /// @brief Maximum normal connection attempts per minute
            inline constexpr size_t MAX_NORMAL_CONNECTION_RATE = 100;

            /// @brief Minimum fast flux IP changes for detection
            inline constexpr size_t MIN_FAST_FLUX_IP_CHANGES = 5;

            /// @brief Fast flux observation window (seconds)
            inline constexpr uint32_t FAST_FLUX_WINDOW_SECONDS = 300;

            /// @brief Minimum entropy for domain randomness
            inline constexpr double MIN_DOMAIN_ENTROPY = 3.5;

            // ========================================================================
            // SCORING WEIGHTS
            // ========================================================================

            /// @brief Weight for internet connectivity checks
            inline constexpr double WEIGHT_CONNECTIVITY_CHECK = 2.0;

            /// @brief Weight for DNS evasion
            inline constexpr double WEIGHT_DNS_EVASION = 3.0;

            /// @brief Weight for DGA detection
            inline constexpr double WEIGHT_DGA_DETECTION = 4.0;

            /// @brief Weight for proxy/VPN/Tor detection
            inline constexpr double WEIGHT_PROXY_DETECTION = 2.5;

            /// @brief Weight for beaconing detection
            inline constexpr double WEIGHT_BEACONING = 3.5;

            /// @brief Weight for C2 infrastructure
            inline constexpr double WEIGHT_C2_INFRASTRUCTURE = 4.5;

            /// @brief Weight for traffic anomalies
            inline constexpr double WEIGHT_TRAFFIC_ANOMALY = 2.0;

            // ========================================================================
            // KNOWN CONNECTIVITY CHECK DOMAINS
            // ========================================================================

            /// @brief Common domains used by malware for connectivity checks
            inline constexpr std::array<std::wstring_view, 20> CONNECTIVITY_CHECK_DOMAINS = { {
                L"google.com", L"microsoft.com", L"apple.com", L"amazon.com",
                L"facebook.com", L"twitter.com", L"youtube.com", L"instagram.com",
                L"linkedin.com", L"github.com", L"stackoverflow.com", L"reddit.com",
                L"wikipedia.org", L"cloudflare.com", L"dns.google", L"one.one.one.one",
                L"msftconnecttest.com", L"connectivitycheck.gstatic.com",
                L"clients3.google.com", L"detectportal.firefox.com"
            } };

            /// @brief Public DNS resolvers (often checked by malware)
            inline constexpr std::array<std::wstring_view, 10> PUBLIC_DNS_RESOLVERS = { {
                L"8.8.8.8", L"8.8.4.4",           // Google DNS
                L"1.1.1.1", L"1.0.0.1",           // Cloudflare DNS
                L"9.9.9.9", L"149.112.112.112",   // Quad9 DNS
                L"208.67.222.222", L"208.67.220.220", // OpenDNS
                L"64.6.64.6", L"64.6.65.6"        // Verisign DNS
            } };

        } // namespace NetworkEvasionConstants

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Categories of network-based evasion techniques
         */
        enum class NetworkEvasionCategory : uint8_t {
            /// @brief Internet connectivity checks
            ConnectivityCheck = 0,

            /// @brief DNS-based evasion
            DNSEvasion = 1,

            /// @brief Network configuration checks
            NetworkConfiguration = 2,

            /// @brief Traffic pattern analysis
            TrafficPattern = 3,

            /// @brief C2 infrastructure
            C2Infrastructure = 4,

            /// @brief Anti-analysis techniques
            AntiAnalysis = 5,

            /// @brief Proxy/VPN/Tor usage
            ProxyDetection = 6,

            /// @brief Beaconing behavior
            Beaconing = 8,

            /// @brief Unknown
            Unknown = 255
        };

        /**
         * @brief Specific network evasion technique identifiers
         */
        enum class NetworkEvasionTechnique : uint16_t {
            /// @brief No technique detected
            None = 0,

            // ========================================================================
            // CONNECTIVITY CHECKS (1-30)
            // ========================================================================

            /// @brief Ping to well-known domains
            CONN_PingKnownDomain = 1,

            /// @brief HTTP GET to connectivity check URLs
            CONN_HTTPConnectivityCheck = 2,

            /// @brief DNS resolution of known domains
            CONN_DNSResolutionCheck = 3,

            /// @brief NTP time sync check
            CONN_NTPTimeCheck = 4,

            /// @brief Network interface enumeration
            CONN_InterfaceEnumeration = 5,

            /// @brief Default gateway check
            CONN_GatewayCheck = 6,

            /// @brief Internet reachability detection
            CONN_ReachabilityDetection = 7,

            /// @brief Checking for active network adapters
            CONN_ActiveAdapterCheck = 8,

            /// @brief Bandwidth measurement
            CONN_BandwidthMeasurement = 9,

            /// @brief Network latency check
            CONN_LatencyCheck = 10,

            // ========================================================================
            // DNS EVASION (31-70)
            // ========================================================================

            /// @brief Domain Generation Algorithm (DGA)
            DNS_DomainGenerationAlgorithm = 31,

            /// @brief Fast flux detection
            DNS_FastFlux = 32,

            /// @brief DNS tunneling
            DNS_Tunneling = 33,

            /// @brief Suspicious TXT record queries
            DNS_SuspiciousTXTQuery = 34,

            /// @brief Excessive DNS lookups
            DNS_ExcessiveLookups = 35,

            /// @brief NXDOMAIN pattern analysis
            DNS_NXDOMAINPattern = 36,

            /// @brief DNS sinkhole detection
            DNS_SinkholeDetection = 37,

            /// @brief Public DNS resolver check
            DNS_PublicResolverCheck = 38,

            /// @brief DNS over HTTPS (DoH) usage
            DNS_DoHUsage = 39,

            /// @brief DNS over TLS (DoT) usage
            DNS_DoTUsage = 40,

            /// @brief Random subdomain generation
            DNS_RandomSubdomain = 41,

            /// @brief DNS cache poisoning attempt
            DNS_CachePoisoning = 42,

            /// @brief High entropy domain names
            DNS_HighEntropyDomain = 43,

            /// @brief Newly registered domain (NRD)
            DNS_NewlyRegisteredDomain = 44,

            /// @brief Domain squatting/typosquatting
            DNS_DomainSquatting = 45,

            // ========================================================================
            // NETWORK CONFIGURATION (71-100)
            // ========================================================================

            /// @brief HTTP/HTTPS proxy detection
            NET_ProxyDetection = 71,

            /// @brief VPN adapter detection
            NET_VPNDetection = 72,

            /// @brief Tor detection
            NET_TorDetection = 73,

            /// @brief NAT detection
            NET_NATDetection = 74,

            /// @brief Firewall rule enumeration
            NET_FirewallEnumeration = 75,

            /// @brief Network isolation detection
            NET_NetworkIsolation = 76,

            /// @brief Restricted network environment
            NET_RestrictedEnvironment = 77,

            /// @brief MAC address randomization check
            NET_MACRandomization = 78,

            /// @brief Multiple network interfaces
            NET_MultipleInterfaces = 79,

            /// @brief Unusual MTU size
            NET_UnusualMTU = 80,

            // ========================================================================
            // TRAFFIC PATTERNS (101-130)
            // ========================================================================

            /// @brief Beaconing behavior detected
            TRAFFIC_Beaconing = 101,

            /// @brief Port scanning behavior
            TRAFFIC_PortScanning = 102,

            /// @brief Unusual protocol usage
            TRAFFIC_UnusualProtocol = 103,

            /// @brief Excessive bandwidth usage
            TRAFFIC_ExcessiveBandwidth = 104,

            /// @brief Traffic volume anomaly
            TRAFFIC_VolumeAnomaly = 105,

            /// @brief Connection rate limiting
            TRAFFIC_RateLimiting = 106,

            /// @brief Suspicious geographic IP
            TRAFFIC_SuspiciousGeoIP = 107,

            /// @brief Encrypted traffic without SNI
            TRAFFIC_EncryptedNoSNI = 108,

            /// @brief Non-standard port usage
            TRAFFIC_NonStandardPort = 109,

            /// @brief Traffic fragmentation
            TRAFFIC_Fragmentation = 110,

            // ========================================================================
            // C2 INFRASTRUCTURE (131-160)
            // ========================================================================

            /// @brief Known C2 domain
            C2_KnownDomain = 131,

            /// @brief Known C2 IP address
            C2_KnownIP = 132,

            /// @brief Bulletproof hosting
            C2_BulletproofHosting = 133,

            /// @brief Cloud provider abuse
            C2_CloudProviderAbuse = 134,

            /// @brief Dynamic DNS usage
            C2_DynamicDNS = 135,

            /// @brief Low domain reputation
            C2_LowReputation = 136,

            /// @brief Self-signed SSL certificate
            C2_SelfSignedCert = 137,

            /// @brief SNI filtering detection
            C2_SNIFiltering = 138,

            /// @brief Suspicious TLD (.tk, .ml, .ga, etc.)
            C2_SuspiciousTLD = 139,

            /// @brief IP address in URL
            C2_IPInURL = 140,

            // ========================================================================
            // ANTI-ANALYSIS (161-190)
            // ========================================================================

            /// @brief Network capture tool detection
            ANTI_NetworkCaptureDetection = 161,

            /// @brief MITM detection
            ANTI_MITMDetection = 162,

            /// @brief SSL inspection detection
            ANTI_SSLInspection = 163,

            /// @brief Traffic monitoring tool detection
            ANTI_MonitoringTool = 164,

            /// @brief Sandbox network detection
            ANTI_SandboxNetwork = 165,

            /// @brief Network latency analysis
            ANTI_LatencyAnalysis = 166,

            /// @brief Bandwidth throttling detection
            ANTI_BandwidthThrottling = 167,

            /// @brief Packet loss rate analysis
            ANTI_PacketLossAnalysis = 168,

            // ========================================================================
            // ADVANCED (191-220)
            // ========================================================================

            /// @brief Multi-stage C2 communication
            ADV_MultiStageC2 = 191,

            /// @brief Domain fronting
            ADV_DomainFronting = 192,

            /// @brief Protocol tunneling
            ADV_ProtocolTunneling = 193,

            /// @brief Steganography in traffic
            ADV_TrafficSteganography = 194,

            /// @brief Covert channel usage
            ADV_CovertChannel = 195,

            /// @brief Living-off-the-land network tools
            ADV_LOLBINNetwork = 196,

            /// @brief Maximum technique ID
            _MaxTechniqueId = 220
        };

        /**
         * @brief Severity level of detected technique
         */
        enum class NetworkEvasionSeverity : uint8_t {
            /// @brief Informational (may be legitimate)
            Low = 0,

            /// @brief Suspicious (warrants investigation)
            Medium = 1,

            /// @brief High confidence malicious
            High = 2,

            /// @brief Critical (active C2 or known threat)
            Critical = 3
        };

        /**
         * @brief Analysis flags for selective scanning
         */
        enum class NetworkAnalysisFlags : uint32_t {
            None = 0,

            // Category flags
            ScanConnectivity = 1 << 0,
            ScanDNS = 1 << 1,
            ScanNetworkConfig = 1 << 2,
            ScanTrafficPatterns = 1 << 3,
            ScanC2Infrastructure = 1 << 4,
            ScanAntiAnalysis = 1 << 5,
            ScanProxyDetection = 1 << 6,
            ScanBeaconing = 1 << 7,

            // Analysis flags
            EnableDNSLookup = 1 << 12,
            EnableHTTPProbe = 1 << 13,
            EnableTrafficCapture = 1 << 14,
            EnableGeoIPLookup = 1 << 15,
            EnableReputationCheck = 1 << 16,

            // Behavior flags
            EnableCaching = 1 << 20,
            EnableRealTimeMonitoring = 1 << 21,
            StopOnFirstDetection = 1 << 22,
            DetailedLogging = 1 << 23,

            // Presets
            QuickScan = ScanConnectivity | ScanDNS | EnableCaching,
            StandardScan = QuickScan | ScanNetworkConfig | ScanC2Infrastructure | EnableReputationCheck,
            DeepScan = StandardScan | ScanTrafficPatterns | ScanAntiAnalysis | EnableGeoIPLookup,
            ComprehensiveScan = 0x00FF | 0x00FF0000 | EnableCaching,

            Default = StandardScan
        };

        // Bitwise operators
        inline constexpr NetworkAnalysisFlags operator|(NetworkAnalysisFlags a, NetworkAnalysisFlags b) noexcept {
            return static_cast<NetworkAnalysisFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
        }

        inline constexpr NetworkAnalysisFlags operator&(NetworkAnalysisFlags a, NetworkAnalysisFlags b) noexcept {
            return static_cast<NetworkAnalysisFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
        }

        inline constexpr bool HasFlag(NetworkAnalysisFlags flags, NetworkAnalysisFlags flag) noexcept {
            return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
        }

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * @brief Get string representation of category
         */
        [[nodiscard]] constexpr const wchar_t* NetworkEvasionCategoryToString(NetworkEvasionCategory category) noexcept {
            switch (category) {
            case NetworkEvasionCategory::ConnectivityCheck:  return L"Connectivity Check";
            case NetworkEvasionCategory::DNSEvasion:         return L"DNS Evasion";
            case NetworkEvasionCategory::NetworkConfiguration: return L"Network Configuration";
            case NetworkEvasionCategory::TrafficPattern:     return L"Traffic Pattern";
            case NetworkEvasionCategory::C2Infrastructure:   return L"C2 Infrastructure";
            case NetworkEvasionCategory::AntiAnalysis:       return L"Anti-Analysis";
            case NetworkEvasionCategory::ProxyDetection:     return L"Proxy Detection";
            case NetworkEvasionCategory::Beaconing:          return L"Beaconing";
            default:                                         return L"Unknown";
            }
        }

        /**
         * @brief Get string representation of technique
         */
        [[nodiscard]] const wchar_t* NetworkEvasionTechniqueToString(NetworkEvasionTechnique technique) noexcept;

        /**
         * @brief Get MITRE ATT&CK ID for technique
         */
        [[nodiscard]] constexpr const char* NetworkEvasionTechniqueToMitreId(NetworkEvasionTechnique technique) noexcept {
            const auto id = static_cast<uint16_t>(technique);

            // Connectivity checks - often part of discovery
            if (id >= 1 && id <= 30) return "T1016"; // System Network Configuration Discovery

            // DNS evasion
            if (id >= 31 && id <= 70) {
                if (id == 31 || id == 32) return "T1568.002"; // DGA
                if (id == 33) return "T1071.004"; // DNS C2
                return "T1071.004"; // DNS Application Layer Protocol
            }

            // Network configuration
            if (id >= 71 && id <= 100) {
                if (id >= 71 && id <= 73) return "T1090"; // Proxy
                return "T1016"; // Network Configuration Discovery
            }

            // Traffic patterns
            if (id >= 101 && id <= 130) return "T1071"; // Application Layer Protocol

            // C2 infrastructure
            if (id >= 131 && id <= 160) return "T1071"; // Application Layer Protocol

            // Anti-analysis
            if (id >= 161 && id <= 190) return "T1205"; // Traffic Signaling

            // Advanced
            if (id >= 191 && id <= 220) {
                if (id == 192) return "T1090.004"; // Domain Fronting
                return "T1573"; // Encrypted Channel
            }

            return "T1071"; // Default
        }

        /**
         * @brief Get category for technique
         */
        [[nodiscard]] constexpr NetworkEvasionCategory GetTechniqueCategory(NetworkEvasionTechnique technique) noexcept {
            const auto id = static_cast<uint16_t>(technique);

            if (id >= 1 && id <= 30)    return NetworkEvasionCategory::ConnectivityCheck;
            if (id >= 31 && id <= 70)   return NetworkEvasionCategory::DNSEvasion;
            if (id >= 71 && id <= 100)  return NetworkEvasionCategory::NetworkConfiguration;
            if (id >= 101 && id <= 130) return NetworkEvasionCategory::TrafficPattern;
            if (id >= 131 && id <= 160) return NetworkEvasionCategory::C2Infrastructure;
            if (id >= 161 && id <= 190) return NetworkEvasionCategory::AntiAnalysis;

            return NetworkEvasionCategory::Unknown;
        }

        /**
         * @brief Get default severity for technique
         */
        [[nodiscard]] constexpr NetworkEvasionSeverity GetDefaultTechniqueSeverity(NetworkEvasionTechnique technique) noexcept {
            switch (technique) {
                // Critical
            case NetworkEvasionTechnique::DNS_DomainGenerationAlgorithm:
            case NetworkEvasionTechnique::C2_KnownDomain:
            case NetworkEvasionTechnique::C2_KnownIP:
            case NetworkEvasionTechnique::TRAFFIC_Beaconing:
            case NetworkEvasionTechnique::ADV_MultiStageC2:
                return NetworkEvasionSeverity::Critical;

                // High
            case NetworkEvasionTechnique::DNS_FastFlux:
            case NetworkEvasionTechnique::DNS_Tunneling:
            case NetworkEvasionTechnique::C2_BulletproofHosting:
            case NetworkEvasionTechnique::C2_DynamicDNS:
            case NetworkEvasionTechnique::ADV_DomainFronting:
                return NetworkEvasionSeverity::High;

                // Medium
            case NetworkEvasionTechnique::CONN_PingKnownDomain:
            case NetworkEvasionTechnique::DNS_ExcessiveLookups:
            case NetworkEvasionTechnique::NET_ProxyDetection:
            case NetworkEvasionTechnique::NET_TorDetection:
                return NetworkEvasionSeverity::Medium;

                // Low (potentially legitimate)
            default:
                return NetworkEvasionSeverity::Low;
            }
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Error information
         */
        struct NetworkEvasionError {
            DWORD win32Code = ERROR_SUCCESS;
            std::wstring message;
            std::wstring context;

            [[nodiscard]] bool HasError() const noexcept { return win32Code != ERROR_SUCCESS; }
            void Clear() noexcept { win32Code = ERROR_SUCCESS; message.clear(); context.clear(); }
        };

        /**
         * @brief Detected technique detail
         */
        struct NetworkDetectedTechnique {
            /// @brief Technique identifier
            NetworkEvasionTechnique technique = NetworkEvasionTechnique::None;

            /// @brief Category
            NetworkEvasionCategory category = NetworkEvasionCategory::Unknown;

            /// @brief Severity
            NetworkEvasionSeverity severity = NetworkEvasionSeverity::Low;

            /// @brief Confidence (0.0 - 1.0)
            double confidence = 0.0;

            /// @brief Weight for scoring
            double weight = 1.0;

            /// @brief Domain/IP/URL involved
            std::wstring target;

            /// @brief Additional context
            std::wstring detectedValue;

            /// @brief Expected value
            std::wstring expectedValue;

            /// @brief Human-readable description
            std::wstring description;

            /// @brief Technical details
            std::wstring technicalDetails;

            /// @brief MITRE ATT&CK ID
            std::string mitreId;

            /// @brief Detection timestamp
            std::chrono::system_clock::time_point detectionTime;

            /// @brief Source of detection
            std::wstring source;

            NetworkDetectedTechnique() = default;
            explicit NetworkDetectedTechnique(NetworkEvasionTechnique tech) noexcept
                : technique(tech)
                , category(GetTechniqueCategory(tech))
                , severity(GetDefaultTechniqueSeverity(tech))
                , mitreId(NetworkEvasionTechniqueToMitreId(tech))
                , detectionTime(std::chrono::system_clock::now())
            {
            }
        };

        /**
         * @brief DNS query information
         */
        struct DNSQueryInfo {
            /// @brief Queried domain
            std::wstring domain;

            /// @brief Query type (A, AAAA, TXT, etc.)
            std::wstring queryType;

            /// @brief Resolved IP addresses
            std::vector<std::wstring> resolvedIPs;

            /// @brief Query timestamp
            std::chrono::system_clock::time_point timestamp;

            /// @brief Query duration (ms)
            uint64_t durationMs = 0;

            /// @brief Success/failure
            bool success = false;

            /// @brief Error message (if failed)
            std::wstring errorMessage;

            /// @brief TTL value
            uint32_t ttl = 0;

            /// @brief Is DGA domain
            bool isDGA = false;

            /// @brief DGA score (0-100)
            double dgaScore = 0.0;

            /// @brief Domain entropy
            double entropy = 0.0;
        };

        /**
         * @brief HTTP connectivity probe information
         */
        struct HTTPProbeInfo {
            /// @brief Target URL
            std::wstring url;

            /// @brief HTTP method
            std::wstring method;

            /// @brief Response code
            uint32_t statusCode = 0;

            /// @brief Response time (ms)
            uint64_t responseTimeMs = 0;

            /// @brief Success/failure
            bool success = false;

            /// @brief Error message
            std::wstring errorMessage;

            /// @brief Response headers
            std::unordered_map<std::wstring, std::wstring> headers;

            /// @brief Is known connectivity check URL
            bool isConnectivityCheck = false;
        };

        /**
         * @brief Beaconing detection information
         */
        struct BeaconingInfo {
            /// @brief Target domain/IP
            std::wstring target;

            /// @brief Connection timestamps
            std::vector<std::chrono::system_clock::time_point> timestamps;

            /// @brief Average interval (seconds)
            double averageIntervalSec = 0.0;

            /// @brief Interval variance
            double intervalVariance = 0.0;

            /// @brief Regularity score (0-1)
            double regularityScore = 0.0;

            /// @brief Is beaconing detected
            bool isBeaconing = false;

            /// @brief Beacon count
            size_t beaconCount = 0;
        };

        /**
         * @brief Fast flux detection information
         */
        struct FastFluxInfo {
            /// @brief Domain name
            std::wstring domain;

            /// @brief IP addresses observed
            std::vector<std::wstring> observedIPs;

            /// @brief IP change timestamps
            std::vector<std::chrono::system_clock::time_point> changeTimestamps;

            /// @brief Total IP changes
            size_t ipChangeCount = 0;

            /// @brief Average TTL
            double averageTTL = 0.0;

            /// @brief Is fast flux detected
            bool isFastFlux = false;
        };

        /**
         * @brief Network configuration information
         */
        struct NetworkConfigInfo {
            /// @brief Has internet connectivity
            bool hasInternetConnectivity = false;

            /// @brief Proxy configured
            bool hasProxy = false;

            /// @brief Proxy address
            std::wstring proxyAddress;

            /// @brief VPN detected
            bool hasVPN = false;

            /// @brief VPN adapter name
            std::wstring vpnAdapter;

            /// @brief Tor detected
            bool hasTor = false;

            /// @brief Public DNS resolver in use
            bool usesPublicDNS = false;

            /// @brief DNS server addresses
            std::vector<std::wstring> dnsServers;

            /// @brief Default gateway
            std::wstring defaultGateway;

            /// @brief Network adapters
            std::vector<std::wstring> adapters;

            /// @brief Is NAT detected
            bool isNATDetected = false;

            /// @brief Valid analysis
            bool valid = false;
        };

        /**
         * @brief Analysis configuration
         */
        struct NetworkAnalysisConfig {
            /// @brief Analysis flags
            NetworkAnalysisFlags flags = NetworkAnalysisFlags::Default;

            /// @brief Timeout in milliseconds
            uint32_t timeoutMs = NetworkEvasionConstants::DEFAULT_ANALYSIS_TIMEOUT_MS;

            /// @brief DNS query timeout
            uint32_t dnsTimeoutMs = NetworkEvasionConstants::DNS_QUERY_TIMEOUT_MS;

            /// @brief HTTP timeout
            uint32_t httpTimeoutMs = NetworkEvasionConstants::HTTP_CONNECTION_TIMEOUT_MS;

            /// @brief Enable caching
            bool enableCaching = true;

            /// @brief Cache TTL
            uint32_t cacheTtlSeconds = NetworkEvasionConstants::RESULT_CACHE_TTL_SECONDS;

            /// @brief Minimum confidence threshold
            double minConfidenceThreshold = 0.5;

            /// @brief Maximum domains to check
            size_t maxDomainsToCheck = NetworkEvasionConstants::MAX_DOMAINS_PER_ANALYSIS;
        };

        /**
         * @brief Comprehensive analysis result
         */
        struct NetworkEvasionResult {
            // ========================================================================
            // IDENTIFICATION
            // ========================================================================

            /// @brief Process ID analyzed
            uint32_t processId = 0;

            /// @brief Process name
            std::wstring processName;

            // ========================================================================
            // DETECTION SUMMARY
            // ========================================================================

            /// @brief Is network evasion detected
            bool isEvasive = false;

            /// @brief Evasion score (0.0 - 100.0)
            double evasionScore = 0.0;

            /// @brief Highest severity
            NetworkEvasionSeverity maxSeverity = NetworkEvasionSeverity::Low;

            /// @brief Total detections
            uint32_t totalDetections = 0;

            /// @brief Categories detected (bitfield)
            uint32_t detectedCategories = 0;

            // ========================================================================
            // DETAILED FINDINGS
            // ========================================================================

            /// @brief All detected techniques
            std::vector<NetworkDetectedTechnique> detectedTechniques;

            /// @brief DNS queries performed
            std::vector<DNSQueryInfo> dnsQueries;

            /// @brief HTTP probes performed
            std::vector<HTTPProbeInfo> httpProbes;

            /// @brief Beaconing information
            std::vector<BeaconingInfo> beacons;

            /// @brief Fast flux detections
            std::vector<FastFluxInfo> fastFluxDomains;

            /// @brief Network configuration
            NetworkConfigInfo networkConfig;

            // ========================================================================
            // INDICATORS
            // ========================================================================

            /// @brief Suspicious domains
            std::vector<std::wstring> suspiciousDomains;

            /// @brief Suspicious IPs
            std::vector<std::wstring> suspiciousIPs;

            /// @brief Known C2 infrastructure
            std::vector<std::wstring> knownC2;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            /// @brief Total DNS queries
            uint32_t totalDNSQueries = 0;

            /// @brief Total HTTP requests
            uint32_t totalHTTPRequests = 0;

            /// @brief Total connections
            uint32_t totalConnections = 0;

            // ========================================================================
            // TIMING & METADATA
            // ========================================================================

            /// @brief Analysis start time
            std::chrono::system_clock::time_point analysisStartTime;

            /// @brief Analysis end time
            std::chrono::system_clock::time_point analysisEndTime;

            /// @brief Duration in milliseconds
            uint64_t analysisDurationMs = 0;

            /// @brief Configuration used
            NetworkAnalysisConfig config;

            /// @brief Analysis completed
            bool analysisComplete = false;

            /// @brief From cache
            bool fromCache = false;

            // ========================================================================
            // METHODS
            // ========================================================================

            [[nodiscard]] bool HasCategory(NetworkEvasionCategory category) const noexcept {
                return (detectedCategories & (1u << static_cast<uint32_t>(category))) != 0;
            }

            [[nodiscard]] bool HasTechnique(NetworkEvasionTechnique technique) const noexcept {
                for (const auto& det : detectedTechniques) {
                    if (det.technique == technique) return true;
                }
                return false;
            }

            void Clear() noexcept {
                processId = 0;
                processName.clear();
                isEvasive = false;
                evasionScore = 0.0;
                maxSeverity = NetworkEvasionSeverity::Low;
                totalDetections = 0;
                detectedCategories = 0;
                detectedTechniques.clear();
                dnsQueries.clear();
                httpProbes.clear();
                beacons.clear();
                fastFluxDomains.clear();
                networkConfig = {};
                suspiciousDomains.clear();
                suspiciousIPs.clear();
                knownC2.clear();
                totalDNSQueries = 0;
                totalHTTPRequests = 0;
                totalConnections = 0;
                analysisStartTime = {};
                analysisEndTime = {};
                analysisDurationMs = 0;
                config = {};
                analysisComplete = false;
                fromCache = false;
            }
        };

        /**
         * @brief Detection callback
         */
        using NetworkDetectionCallback = std::function<void(
            uint32_t processId,
            const NetworkDetectedTechnique& detection
            )>;

        /**
         * @brief Progress callback
         */
        using NetworkProgressCallback = std::function<void(
            uint32_t processId,
            NetworkEvasionCategory currentCategory,
            uint32_t checksCompleted,
            uint32_t totalChecks
            )>;

        // ============================================================================
        // MAIN DETECTOR CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade network-based evasion detector
         *
         * Detects malware that checks network characteristics and behaviors
         * to evade sandbox/analysis environments. Thread-safe for concurrent analysis.
         *
         * Usage example:
         * @code
         *     auto detector = std::make_unique<NetworkBasedEvasionDetector>();
         *     if (!detector->Initialize()) {
         *         // Handle failure
         *     }
         *
         *     NetworkAnalysisConfig config;
         *     config.flags = NetworkAnalysisFlags::DeepScan;
         *
         *     auto result = detector->AnalyzeProcess(processId, config);
         *     if (result.isEvasive) {
         *         std::wcout << L"Evasion score: " << result.evasionScore << L"%\n";
         *     }
         * @endcode
         */
        class NetworkBasedEvasionDetector {
        public:
            // ========================================================================
            // CONSTRUCTION & LIFECYCLE
            // ========================================================================

            /**
             * @brief Default constructor
             */
            NetworkBasedEvasionDetector() noexcept;

            /**
             * @brief Constructor with threat intel
             */
            explicit NetworkBasedEvasionDetector(
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
            ) noexcept;

            /**
             * @brief Destructor
             */
            ~NetworkBasedEvasionDetector();

            // Non-copyable, movable
            NetworkBasedEvasionDetector(const NetworkBasedEvasionDetector&) = delete;
            NetworkBasedEvasionDetector& operator=(const NetworkBasedEvasionDetector&) = delete;
            NetworkBasedEvasionDetector(NetworkBasedEvasionDetector&&) noexcept;
            NetworkBasedEvasionDetector& operator=(NetworkBasedEvasionDetector&&) noexcept;

            // ========================================================================
            // INITIALIZATION
            // ========================================================================

            /**
             * @brief Initialize the detector
             */
            [[nodiscard]] bool Initialize(NetworkEvasionError* err = nullptr) noexcept;

            /**
             * @brief Shutdown
             */
            void Shutdown() noexcept;

            /**
             * @brief Check if initialized
             */
            [[nodiscard]] bool IsInitialized() const noexcept;

            // ========================================================================
            // PROCESS ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze process network activity
             */
            [[nodiscard]] NetworkEvasionResult AnalyzeProcess(
                uint32_t processId,
                const NetworkAnalysisConfig& config = NetworkAnalysisConfig{},
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze process using handle
             */
            [[nodiscard]] NetworkEvasionResult AnalyzeProcess(
                HANDLE hProcess,
                const NetworkAnalysisConfig& config = NetworkAnalysisConfig{},
                NetworkEvasionError* err = nullptr
            ) noexcept;

            // ========================================================================
            // DOMAIN/URL ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze single domain
             */
            [[nodiscard]] bool AnalyzeDomain(
                std::wstring_view domain,
                std::vector<NetworkDetectedTechnique>& outDetections,
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze multiple domains
             */
            [[nodiscard]] bool AnalyzeDomains(
                const std::vector<std::wstring>& domains,
                std::vector<NetworkDetectedTechnique>& outDetections,
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Check if domain is DGA-generated
             */
            [[nodiscard]] bool IsDGADomain(
                std::wstring_view domain,
                double& outScore,
                NetworkEvasionError* err = nullptr
            ) noexcept;

            // ========================================================================
            // NETWORK CHECKS
            // ========================================================================

            /**
             * @brief Check internet connectivity
             */
            [[nodiscard]] bool CheckInternetConnectivity(
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Detect proxy configuration
             */
            [[nodiscard]] bool DetectProxy(
                std::wstring& outProxyAddress,
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Detect VPN
             */
            [[nodiscard]] bool DetectVPN(
                std::wstring& outVPNAdapter,
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Detect Tor
             */
            [[nodiscard]] bool DetectTor(
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Detect beaconing behavior
             */
            [[nodiscard]] bool DetectBeaconing(
                const std::vector<std::chrono::system_clock::time_point>& timestamps,
                BeaconingInfo& outInfo,
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Detect fast flux
             */
            [[nodiscard]] bool DetectFastFlux(
                std::wstring_view domain,
                FastFluxInfo& outInfo,
                NetworkEvasionError* err = nullptr
            ) noexcept;

            // ========================================================================
            // REAL-TIME MONITORING
            // ========================================================================

            /**
             * @brief Start real-time network monitoring
             */
            [[nodiscard]] bool StartMonitoring(
                uint32_t processId,
                const NetworkAnalysisConfig& config = NetworkAnalysisConfig{},
                NetworkEvasionError* err = nullptr
            ) noexcept;

            /**
             * @brief Stop real-time monitoring
             */
            void StopMonitoring(uint32_t processId) noexcept;

            /**
             * @brief Stop all monitoring
             */
            void StopAllMonitoring() noexcept;

            // ========================================================================
            // CALLBACKS
            // ========================================================================

            /**
             * @brief Set detection callback
             */
            void SetDetectionCallback(NetworkDetectionCallback callback) noexcept;

            /**
             * @brief Clear detection callback
             */
            void ClearDetectionCallback() noexcept;

            // ========================================================================
            // CACHING
            // ========================================================================

            /**
             * @brief Get cached result
             */
            [[nodiscard]] std::optional<NetworkEvasionResult> GetCachedResult(
                uint32_t processId
            ) const noexcept;

            /**
             * @brief Invalidate cache entry
             */
            void InvalidateCache(uint32_t processId) noexcept;

            /**
             * @brief Clear all cache
             */
            void ClearCache() noexcept;

            /**
             * @brief Get cache size
             */
            [[nodiscard]] size_t GetCacheSize() const noexcept;

            // ========================================================================
            // CONFIGURATION
            // ========================================================================

            /**
             * @brief Set threat intel store
             */
            void SetThreatIntelStore(
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
            ) noexcept;

            /**
             * @brief Add known C2 domain
             */
            void AddKnownC2Domain(std::wstring_view domain) noexcept;

            /**
             * @brief Add known C2 IP
             */
            void AddKnownC2IP(std::wstring_view ip) noexcept;

            /**
             * @brief Clear custom lists
             */
            void ClearCustomLists() noexcept;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            struct Statistics {
                std::atomic<uint64_t> totalAnalyses{ 0 };
                std::atomic<uint64_t> totalDetections{ 0 };
                std::atomic<uint64_t> evasiveProcesses{ 0 };
                std::atomic<uint64_t> totalDNSQueries{ 0 };
                std::atomic<uint64_t> totalHTTPRequests{ 0 };
                std::atomic<uint64_t> dgaDetections{ 0 };
                std::atomic<uint64_t> beaconingDetections{ 0 };
                std::atomic<uint64_t> c2Detections{ 0 };
                std::atomic<uint64_t> cacheHits{ 0 };
                std::atomic<uint64_t> cacheMisses{ 0 };
                std::atomic<uint64_t> analysisErrors{ 0 };
                std::atomic<uint64_t> totalAnalysisTimeUs{ 0 };
                std::array<std::atomic<uint64_t>, 16> categoryDetections{};

                void Reset() noexcept {
                    totalAnalyses = 0;
                    evasiveProcesses = 0;
                    totalDNSQueries = 0;
                    totalHTTPRequests = 0;
                    dgaDetections = 0;
                    beaconingDetections = 0;
                    c2Detections = 0;
                    cacheHits = 0;
                    cacheMisses = 0;
                    analysisErrors = 0;
                    totalAnalysisTimeUs = 0;
                    for (auto& cat : categoryDetections) cat = 0;
                }
            };

            [[nodiscard]] const Statistics& GetStatistics() const noexcept;
            void ResetStatistics() noexcept;

        private:
            class Impl;
            std::unique_ptr<Impl> m_impl;

            void AnalyzeProcessInternal(
                HANDLE hProcess,
                uint32_t processId,
                const NetworkAnalysisConfig& config,
                NetworkEvasionResult& result
            ) noexcept;

            void CheckConnectivity(
                NetworkEvasionResult& result
            ) noexcept;

            void CheckDNSEvasion(
                const std::vector<std::chrono::system_clock::time_point>& timestamps,
                const std::unordered_map<std::wstring, std::vector<std::wstring>>& domainToIPs,
                NetworkEvasionResult& result
            ) noexcept;

            void CheckNetworkConfiguration(
                NetworkEvasionResult& result
            ) noexcept;

            void CheckTrafficPatterns(
                const std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>>& targetTimestamps,
                NetworkEvasionResult& result
            ) noexcept;

            void CheckBeaconing(
                const std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>>& targetTimestamps,
                NetworkEvasionResult& result
            ) noexcept;

            void CheckC2Infrastructure(
                const std::vector<std::wstring>& domains,
                const std::vector<std::wstring>& ips,
                NetworkEvasionResult& result
            ) noexcept;

            void CalculateEvasionScore(NetworkEvasionResult& result) noexcept;

            void AddDetection(
                NetworkEvasionResult& result,
                NetworkDetectedTechnique detection
            ) noexcept;

            void UpdateCache(
                uint32_t processId,
                const NetworkEvasionResult& result
            ) noexcept;

            double CalculateDomainEntropy(std::wstring_view domain) const noexcept;
            double CalculateDGAScore(std::wstring_view domain) const noexcept;
        };

    } // namespace AntiEvasion
} // namespace ShadowStrike
