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
 *
 * ============================================================================
 * DETECTION CAPABILITIES
 * ============================================================================
 *
 * 1. DGA DETECTION
 *    - Shannon entropy calculation
 *    - N-gram frequency analysis
 *    - Vowel/consonant ratio analysis
 *    - Character distribution analysis
 *    - Markov chain probability scoring
 *    - Dictionary word detection
 *
 * 2. DNS TUNNELING DETECTION
 *    - Subdomain length analysis
 *    - Query payload entropy
 *    - TXT record abuse detection
 *    - Excessive query rate detection
 *    - Base64/Hex encoded subdomain detection
 *
 * 3. BEACONING DETECTION
 *    - Interval regularity analysis
 *    - Jitter tolerance calculation
 *    - Multi-interval pattern detection
 *    - Connection frequency analysis
 *
 * 4. FAST FLUX DETECTION
 *    - IP change frequency monitoring
 *    - TTL analysis
 *    - Geographic dispersion detection
 *
 * 5. C2 INFRASTRUCTURE DETECTION
 *    - Domain reputation via ThreatIntel
 *    - Dynamic DNS provider detection
 *    - Suspicious TLD detection
 *    - Self-signed certificate detection
 *    - Domain fronting detection
 *
 * 6. NETWORK CAPTURE TOOL DETECTION
 *    - Process enumeration for known tools
 *    - Network driver detection
 *    - Promiscuous mode detection
 *
 * 7. ANTI-ANALYSIS DETECTION
 *    - Sandbox network fingerprinting
 *    - MITM detection via certificate validation
 *    - SSL inspection detection
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
#include <cwctype>
#include <regex>
#include <sstream>
#include <format>
#include <cctype>
#include <iomanip>
#include <bitset>
#include <random>
#include <span>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

#include <wininet.h>
#pragma comment(lib, "wininet.lib")

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#include <TlHelp32.h>

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"
#include "../ThreatIntel/ThreatIntelFormat.hpp"

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // LOGGING CATEGORY
    // ========================================================================

    static constexpr const wchar_t* LOG_CATEGORY = L"NetworkEvasion";

    // ========================================================================
    // INTERNAL CONSTANTS
    // ========================================================================

    namespace {

        /// @brief Known network capture tool process names
        const std::vector<std::wstring> NETWORK_CAPTURE_TOOLS = {
            L"wireshark.exe", L"tshark.exe", L"dumpcap.exe",
            L"fiddler.exe", L"charles.exe", L"burpsuite.exe",
            L"mitmproxy.exe", L"proxifier.exe",
            L"tcpdump.exe", L"windump.exe",
            L"netmon.exe", L"nmcap.exe",
            L"smartsniff.exe", L"rawcap.exe",
            L"httpwatch.exe", L"iewatch.exe",
            L"procmon.exe", L"tcpview.exe",
            L"currports.exe", L"cports.exe",
            L"commview.exe", L"networkmonitor.exe"
        };

        /// @brief Known Dynamic DNS providers
        const std::vector<std::wstring> DDNS_PROVIDERS = {
            L"no-ip.com", L"noip.com", L"dyndns.org", L"dyndns.com",
            L"dynu.com", L"dynu.net", L"freedns.afraid.org",
            L"changeip.com", L"duckdns.org", L"hopto.org",
            L"zapto.org", L"sytes.net", L"serveftp.com",
            L"ddns.net", L"myftp.biz", L"myftp.org",
            L"servegame.com", L"servehttp.com", L"servepics.com",
            L"webhop.me", L"redirectme.net", L"bounceme.net",
            L"myddns.me", L"mooo.com", L"strangled.net",
            L"3utilities.com", L"blogsyte.com", L"gotdns.ch",
            L"gotdns.com", L"gotdns.org"
        };

        /// @brief Suspicious TLDs often used by malware
        const std::vector<std::wstring> SUSPICIOUS_TLDS = {
            L"tk", L"ml", L"ga", L"cf", L"gq",      // Free TLDs
            L"xyz", L"top", L"work", L"click",       // Cheap TLDs
            L"link", L"loan", L"trade", L"win",
            L"review", L"party", L"racing", L"download",
            L"bid", L"stream", L"gdn", L"men",
            L"accountant", L"science", L"faith", L"cricket",
            L"date", L"webcam", L"su", L"cc",
            L"ws", L"pw", L"bz", L"to",
            L"nu", L"cm", L"ru", L"cn",             // Country TLDs sometimes abused
            L"buzz", L"monster", L"rest", L"surf"
        };

        // ====================================================================
        // FP FIX #3: Cloud Provider Detection - Tiered Approach
        // The original list included mainstream services (Discord, Telegram)
        // used by hundreds of millions of legitimate users.
        // 
        // NEW APPROACH:
        // - Tier 1 (SUSPICIOUS): Services frequently abused by malware for C2
        // - Tier 2 (INFORMATIONAL): Mainstream cloud - only flag with other indicators
        // Discord and Telegram REMOVED - they are legitimate communication tools
        // ====================================================================

        /// @brief Highly suspicious cloud services (known C2 abuse vectors)
        /// These warrant higher confidence flagging
        const std::vector<std::wstring> SUSPICIOUS_CLOUD_SERVICES = {
            L"ngrok.io", L"serveo.net",           // Tunneling services (common C2)
            L"pastebin.com", L"paste.ee", L"ghostbin.com", // Paste sites (payload hosting)
            L"transfer.sh", L"file.io",            // Anonymous file sharing
            L"requestbin.com", L"webhook.site"     // Data exfil endpoints
        };

        /// @brief Mainstream cloud providers - informational only
        /// Flagging these with high confidence would cause massive false positives
        const std::vector<std::wstring> CLOUD_PROVIDERS = {
            L"amazonaws.com", L"cloudfront.net", L"s3.amazonaws.com",
            L"azure.com", L"azurewebsites.net", L"blob.core.windows.net",
            L"googleusercontent.com", L"storage.googleapis.com", L"appspot.com",
            L"firebaseio.com", L"firebaseapp.com",
            L"cloudflare.com", L"workers.dev",
            L"digitaloceanspaces.com", L"do.co",
            L"herokuapp.com", L"heroku.com",
            L"netlify.app", L"vercel.app"
            // NOTE: Discord and Telegram REMOVED - legitimate communication platforms
            // used by millions of enterprises for team collaboration
        };

        /// @brief Known Tor exit node ports
        constexpr uint16_t TOR_SOCKS_PORT = 9050;
        constexpr uint16_t TOR_BROWSER_PORT = 9150;
        constexpr uint16_t TOR_CONTROL_PORT = 9051;

        /// @brief Common English bigrams for DGA detection
        const std::vector<std::string> COMMON_BIGRAMS = {
            "th", "he", "in", "en", "nt", "re", "er", "an", "ti", "es",
            "on", "at", "se", "nd", "or", "ar", "al", "te", "co", "de",
            "to", "ra", "et", "ed", "it", "sa", "em", "ro", "st", "ng"
        };

        /// @brief Uncommon consonant clusters (rare in legitimate words)
        const std::vector<std::string> RARE_CONSONANT_CLUSTERS = {
            "xq", "qx", "zx", "xz", "jq", "qj", "vq", "qv",
            "bx", "xb", "cx", "xc", "dx", "xd", "fx", "xf",
            "gx", "xg", "hx", "xh", "jx", "xj", "kx", "xk",
            "lx", "xl", "mx", "xm", "nx", "xn", "px", "xp",
            "rx", "xr", "sx", "xs", "tx", "xt", "vx", "xv",
            "wx", "xw", "zq", "qz", "zj", "jz", "zv", "vz"
        };

        /// @brief Maximum subdomain length for normal domains
        constexpr size_t MAX_NORMAL_SUBDOMAIN_LENGTH = 32;

        /// @brief Maximum total subdomain labels
        constexpr size_t MAX_NORMAL_LABEL_COUNT = 5;

        /// @brief Entropy threshold for DNS tunneling
        constexpr double DNS_TUNNEL_ENTROPY_THRESHOLD = 4.0;

        /// @brief Minimum subdomain length for tunnel detection
        constexpr size_t MIN_TUNNEL_SUBDOMAIN_LENGTH = 20;

    } // anonymous namespace

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

        /// @brief Statistics (mutable for const functions to update atomics)
        mutable NetworkBasedEvasionDetector::Statistics m_stats;

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
            std::unordered_map<std::wstring, uint32_t> nxdomainCounts;
            std::unordered_map<std::wstring, std::vector<uint32_t>> domainTTLs;
        };
        std::unordered_map<uint32_t, DNSTracker> m_dnsTracking;

        /// @brief Connection tracking (for beaconing detection)
        struct ConnectionTracker {
            std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>> targetTimestamps;
            std::map<std::wstring, std::vector<size_t>> targetByteCounts;
            std::unordered_set<uint16_t> usedPorts;
        };
        std::unordered_map<uint32_t, ConnectionTracker> m_connectionTracking;

        /// @brief Known C2 domains/IPs (custom lists)
        std::unordered_set<std::wstring> m_knownC2Domains;
        std::unordered_set<std::wstring> m_knownC2IPs;

        /// @brief Monitoring state
        std::unordered_map<uint32_t, NetworkAnalysisConfig> m_monitoringProcesses;
        std::atomic<bool> m_monitoringActive{ false };

        /// @brief N-gram frequency table for DGA detection
        std::unordered_map<std::string, double> m_bigramFrequencies;

        /// @brief Domain reputation cache
        struct DomainReputationEntry {
            double score;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<std::wstring, DomainReputationEntry> m_domainReputationCache;

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() {
            InitializeBigramFrequencies();
        }
        ~Impl() = default;

        [[nodiscard]] bool Initialize(NetworkEvasionError* err) noexcept;
        void Shutdown() noexcept;

        // Bigram initialization for DGA detection
        void InitializeBigramFrequencies() noexcept;

        // ================================================================
        // ENTROPY AND DGA DETECTION
        // ================================================================

        /// @brief Calculate Shannon entropy for domain names
        [[nodiscard]] double CalculateDomainEntropy(std::wstring_view domain) const noexcept;

        /// @brief Calculate comprehensive DGA score
        [[nodiscard]] double CalculateDGAScore(std::wstring_view domain) const noexcept;

        /// @brief Calculate n-gram score for domain
        [[nodiscard]] double CalculateNGramScore(std::wstring_view domain) const noexcept;

        /// @brief Calculate vowel/consonant ratio score
        [[nodiscard]] double CalculateVowelConsonantScore(std::wstring_view domain) const noexcept;

        /// @brief Check for rare consonant clusters
        [[nodiscard]] double CalculateConsonantClusterScore(std::wstring_view domain) const noexcept;

        /// @brief Check for numeric patterns in domain
        [[nodiscard]] double CalculateNumericPatternScore(std::wstring_view domain) const noexcept;

        /// @brief Calculate character distribution uniformity
        [[nodiscard]] double CalculateDistributionUniformity(std::wstring_view domain) const noexcept;

        // ================================================================
        // DNS TUNNELING DETECTION
        // ================================================================

        /// @brief Detect DNS tunneling patterns
        [[nodiscard]] bool DetectDNSTunneling(
            std::wstring_view domain,
            double& outConfidence,
            std::wstring& outDetails
        ) const noexcept;

        /// @brief Check for Base64/Hex encoded subdomains
        [[nodiscard]] bool IsEncodedSubdomain(std::wstring_view subdomain) const noexcept;

        /// @brief Calculate subdomain entropy
        [[nodiscard]] double CalculateSubdomainEntropy(std::wstring_view domain) const noexcept;

        // ================================================================
        // BEACONING DETECTION
        // ================================================================

        /// @brief Calculate beaconing regularity with jitter tolerance
        [[nodiscard]] double CalculateBeaconingRegularity(
            const std::vector<std::chrono::system_clock::time_point>& timestamps
        ) const noexcept;

        /// @brief Detect multiple beacon intervals (sophisticated C2)
        [[nodiscard]] bool DetectMultiIntervalBeaconing(
            const std::vector<std::chrono::system_clock::time_point>& timestamps,
            std::vector<double>& detectedIntervals
        ) const noexcept;

        /// @brief Calculate jitter percentage
        [[nodiscard]] double CalculateJitterPercentage(
            const std::vector<double>& intervals
        ) const noexcept;

        // ================================================================
        // NETWORK ADAPTER ANALYSIS
        // ================================================================

        /// @brief Check network adapters using GetAdaptersAddresses (Modern API)
        [[nodiscard]] bool CheckNetworkAdapters(
            bool& outVpnDetected,
            std::wstring& outVpnName,
            bool& outVmMacDetected,
            std::wstring& outVmMacInfo,
            std::vector<std::wstring>& outAdapterDetails,
            NetworkEvasionError* err
        ) const noexcept;

        /// @brief Detect sandbox-specific network configurations
        [[nodiscard]] bool DetectSandboxNetwork(
            std::wstring& outDetails
        ) const noexcept;

        // ================================================================
        // NETWORK CAPTURE TOOL DETECTION
        // ================================================================

        /// @brief Detect running network capture tools
        [[nodiscard]] bool DetectNetworkCaptureTools(
            std::vector<std::wstring>& detectedTools
        ) const noexcept;

        /// @brief Check for promiscuous mode on adapters
        [[nodiscard]] bool DetectPromiscuousMode() const noexcept;

        // ================================================================
        // C2 INFRASTRUCTURE DETECTION
        // ================================================================

        /// @brief Check if domain uses Dynamic DNS provider
        [[nodiscard]] bool IsDynamicDNSDomain(std::wstring_view domain) const noexcept;

        /// @brief Check if domain has suspicious TLD
        [[nodiscard]] bool HasSuspiciousTLD(std::wstring_view domain) const noexcept;

        /// @brief Detect cloud provider abuse
        [[nodiscard]] bool IsCloudProviderDomain(std::wstring_view domain) const noexcept;

        /// @brief Check SSL certificate for anomalies
        [[nodiscard]] bool CheckSSLCertificate(
            std::wstring_view domain,
            bool& outSelfSigned,
            bool& outExpired,
            bool& outMismatch,
            std::wstring& outDetails
        ) const noexcept;

        /// @brief Detect domain fronting
        [[nodiscard]] bool DetectDomainFronting(
            std::wstring_view requestedHost,
            std::wstring_view sniHost,
            std::wstring& outDetails
        ) const noexcept;

        // ================================================================
        // VALIDATION HELPERS
        // ================================================================

        /// @brief Domain validation
        [[nodiscard]] bool IsValidDomain(std::wstring_view domain) const noexcept;

        /// @brief IP validation
        [[nodiscard]] bool IsValidIPv4(std::wstring_view ip) const noexcept;

        /// @brief Check if domain is in connectivity check list
        [[nodiscard]] bool IsConnectivityCheckDomain(std::wstring_view domain) const noexcept;

        /// @brief Check if IP is public DNS resolver
        [[nodiscard]] bool IsPublicDNSResolver(std::wstring_view ip) const noexcept;

        /// @brief Parse TLD from domain
        [[nodiscard]] std::wstring GetTLD(std::wstring_view domain) const noexcept;

        /// @brief Extract second-level domain
        [[nodiscard]] std::wstring GetSecondLevelDomain(std::wstring_view domain) const noexcept;

        /// @brief Count subdomain labels
        [[nodiscard]] size_t CountSubdomainLabels(std::wstring_view domain) const noexcept;

        /// @brief Get longest subdomain label
        [[nodiscard]] std::wstring GetLongestSubdomainLabel(std::wstring_view domain) const noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    void NetworkBasedEvasionDetector::Impl::InitializeBigramFrequencies() noexcept {
        // Initialize with common English bigram frequencies (normalized)
        // These values approximate the frequency of common letter pairs
        m_bigramFrequencies = {
            {"th", 0.0356}, {"he", 0.0307}, {"in", 0.0243}, {"en", 0.0225},
            {"nt", 0.0117}, {"re", 0.0185}, {"er", 0.0205}, {"an", 0.0199},
            {"ti", 0.0134}, {"es", 0.0132}, {"on", 0.0176}, {"at", 0.0149},
            {"se", 0.0093}, {"nd", 0.0135}, {"or", 0.0136}, {"ar", 0.0107},
            {"al", 0.0109}, {"te", 0.0121}, {"co", 0.0079}, {"de", 0.0076},
            {"to", 0.0108}, {"ra", 0.0078}, {"et", 0.0076}, {"ed", 0.0128},
            {"it", 0.0112}, {"sa", 0.0059}, {"em", 0.0057}, {"ro", 0.0073},
            {"st", 0.0105}, {"ng", 0.0095}, {"le", 0.0085}, {"is", 0.0086},
            {"ou", 0.0087}, {"ea", 0.0069}, {"io", 0.0083}, {"as", 0.0066},
            {"ve", 0.0083}, {"of", 0.0066}, {"ha", 0.0073}, {"ri", 0.0073},
            {"ne", 0.0065}, {"me", 0.0061}, {"no", 0.0058}, {"ll", 0.0058},
            {"ee", 0.0038}, {"tt", 0.0016}, {"ss", 0.0040}, {"oo", 0.0021},
            {"ff", 0.0010}, {"rr", 0.0012}, {"nn", 0.0007}, {"pp", 0.0008}
        };
    }

    bool NetworkBasedEvasionDetector::Impl::Initialize(NetworkEvasionError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            SS_LOG_INFO(LOG_CATEGORY, L"NetworkBasedEvasionDetector: Initializing...");

            // Initialize Winsock
            WSADATA wsaData;
            const int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (wsaResult != 0) {
                SS_LOG_ERROR(LOG_CATEGORY, L"NetworkBasedEvasionDetector: WSAStartup failed: %d", wsaResult);

                if (err) {
                    err->win32Code = wsaResult;
                    err->message = L"WSAStartup failed";
                }

                m_initialized = false;
                return false;
            }

            // Initialize bigram frequencies for DGA detection
            InitializeBigramFrequencies();

            SS_LOG_INFO(LOG_CATEGORY, L"NetworkBasedEvasionDetector: Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"NetworkBasedEvasionDetector initialization failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"NetworkBasedEvasionDetector: Unknown initialization error");

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

            SS_LOG_INFO(LOG_CATEGORY, L"NetworkBasedEvasionDetector: Shutting down...");

            // Stop monitoring
            m_monitoringActive = false;
            m_monitoringProcesses.clear();

            // Clear caches
            m_resultCache.clear();
            m_dnsTracking.clear();
            m_connectionTracking.clear();
            m_domainReputationCache.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            // Cleanup Winsock
            WSACleanup();

            SS_LOG_INFO(LOG_CATEGORY, L"NetworkBasedEvasionDetector: Shutdown complete");
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"NetworkBasedEvasionDetector: Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: ENTROPY AND DGA DETECTION
    // ========================================================================

    double NetworkBasedEvasionDetector::Impl::CalculateDomainEntropy(std::wstring_view domain) const noexcept {
        if (domain.empty()) {
            return 0.0;
        }

        try {
            // Remove TLD for entropy calculation
            size_t lastDot = domain.find_last_of(L'.');
            std::wstring domainPart = (lastDot != std::wstring::npos)
                ? std::wstring(domain.substr(0, lastDot))
                : std::wstring(domain);

            // Remove dots for pure character entropy
            std::wstring chars;
            for (wchar_t c : domainPart) {
                if (c != L'.') {
                    chars += std::towlower(c);
                }
            }

            if (chars.empty()) {
                return 0.0;
            }

            // Count character frequencies
            std::array<uint64_t, 256> counts{};
            for (wchar_t c : chars) {
                if (c < 256) {
                    counts[c]++;
                }
            }

            // Calculate Shannon entropy
            double entropy = 0.0;
            const double size = static_cast<double>(chars.size());

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

    double NetworkBasedEvasionDetector::Impl::CalculateNGramScore(std::wstring_view domain) const noexcept {
        if (domain.length() < 2) {
            return 0.0;
        }

        try {
            // Extract domain name without TLD
            size_t lastDot = domain.find_last_of(L'.');
            std::wstring domainPart = (lastDot != std::wstring::npos)
                ? std::wstring(domain.substr(0, lastDot))
                : std::wstring(domain);

            // Remove subdomain parts - get the second-level domain
            size_t firstDot = domainPart.find(L'.');
            if (firstDot != std::wstring::npos) {
                domainPart = domainPart.substr(firstDot + 1);
            }

            // Convert to lowercase narrow string for bigram lookup
            std::string narrowDomain;
            for (wchar_t c : domainPart) {
                if (c != L'.' && c < 128) {
                    narrowDomain += static_cast<char>(std::tolower(c));
                }
            }

            if (narrowDomain.length() < 2) {
                return 50.0; // Neutral score
            }

            // Calculate average bigram probability
            double totalProb = 0.0;
            size_t bigramCount = 0;

            for (size_t i = 0; i < narrowDomain.length() - 1; ++i) {
                std::string bigram = narrowDomain.substr(i, 2);
                auto it = m_bigramFrequencies.find(bigram);
                if (it != m_bigramFrequencies.end()) {
                    totalProb += it->second;
                }
                // Missing bigrams add 0, indicating rare combination
                bigramCount++;
            }

            if (bigramCount == 0) {
                return 100.0; // No bigrams = suspicious
            }

            double avgProb = totalProb / bigramCount;

            // Lower average probability = more DGA-like
            // Legitimate domains have avgProb around 0.01-0.02
            // DGA domains typically have avgProb < 0.005

            if (avgProb < 0.002) return 100.0;
            if (avgProb < 0.005) return 80.0;
            if (avgProb < 0.008) return 60.0;
            if (avgProb < 0.012) return 40.0;
            if (avgProb < 0.015) return 20.0;
            return 0.0;
        }
        catch (...) {
            return 0.0;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateVowelConsonantScore(std::wstring_view domain) const noexcept {
        try {
            // Extract domain name without TLD
            size_t lastDot = domain.find_last_of(L'.');
            std::wstring domainPart = (lastDot != std::wstring::npos)
                ? std::wstring(domain.substr(0, lastDot))
                : std::wstring(domain);

            size_t vowels = 0;
            size_t consonants = 0;
            size_t consecutiveConsonants = 0;
            size_t maxConsecutiveConsonants = 0;

            for (wchar_t c : domainPart) {
                c = std::towlower(c);
                if (c == L'a' || c == L'e' || c == L'i' || c == L'o' || c == L'u') {
                    vowels++;
                    maxConsecutiveConsonants = std::max(maxConsecutiveConsonants, consecutiveConsonants);
                    consecutiveConsonants = 0;
                }
                else if (std::iswalpha(c)) {
                    consonants++;
                    consecutiveConsonants++;
                }
            }
            maxConsecutiveConsonants = std::max(maxConsecutiveConsonants, consecutiveConsonants);

            double score = 0.0;

            // Check vowel ratio
            if (vowels + consonants > 0) {
                double vowelRatio = static_cast<double>(vowels) / (vowels + consonants);

                // Normal English words have ~38% vowels
                // DGA domains often have either very few or unusual distribution
                if (vowelRatio < 0.15 || vowelRatio > 0.60) {
                    score += 40.0;
                }
                else if (vowelRatio < 0.25 || vowelRatio > 0.50) {
                    score += 20.0;
                }
            }

            // Check consonant clustering
            if (maxConsecutiveConsonants >= 5) {
                score += 40.0;
            }
            else if (maxConsecutiveConsonants >= 4) {
                score += 25.0;
            }
            else if (maxConsecutiveConsonants >= 3) {
                score += 10.0;
            }

            // No vowels at all is very suspicious
            if (vowels == 0 && consonants > 3) {
                score += 30.0;
            }

            return std::min(score, 100.0);
        }
        catch (...) {
            return 0.0;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateConsonantClusterScore(std::wstring_view domain) const noexcept {
        try {
            std::string narrowDomain;
            for (wchar_t c : domain) {
                if (c != L'.' && c < 128) {
                    narrowDomain += static_cast<char>(std::tolower(c));
                }
            }

            if (narrowDomain.length() < 2) {
                return 0.0;
            }

            size_t rareClusterCount = 0;

            for (const auto& cluster : RARE_CONSONANT_CLUSTERS) {
                if (narrowDomain.find(cluster) != std::string::npos) {
                    rareClusterCount++;
                }
            }

            // Multiple rare clusters is highly suspicious
            if (rareClusterCount >= 3) return 100.0;
            if (rareClusterCount >= 2) return 70.0;
            if (rareClusterCount >= 1) return 40.0;
            return 0.0;
        }
        catch (...) {
            return 0.0;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateNumericPatternScore(std::wstring_view domain) const noexcept {
        try {
            // Extract domain name without TLD
            size_t lastDot = domain.find_last_of(L'.');
            std::wstring domainPart = (lastDot != std::wstring::npos)
                ? std::wstring(domain.substr(0, lastDot))
                : std::wstring(domain);

            size_t digitCount = 0;
            size_t consecutiveDigits = 0;
            size_t maxConsecutiveDigits = 0;
            bool hasDigitLetterMix = false;
            bool prevWasDigit = false;

            for (wchar_t c : domainPart) {
                if (c == L'.') {
                    prevWasDigit = false;
                    continue;
                }

                bool isDigit = std::iswdigit(c);
                if (isDigit) {
                    digitCount++;
                    consecutiveDigits++;
                    if (!prevWasDigit && consecutiveDigits == 1) {
                        hasDigitLetterMix = true;
                    }
                }
                else {
                    maxConsecutiveDigits = std::max(maxConsecutiveDigits, consecutiveDigits);
                    consecutiveDigits = 0;
                    if (prevWasDigit) {
                        hasDigitLetterMix = true;
                    }
                }
                prevWasDigit = isDigit;
            }
            maxConsecutiveDigits = std::max(maxConsecutiveDigits, consecutiveDigits);

            double score = 0.0;

            // High digit ratio in domain name is suspicious
            if (domainPart.length() > 0) {
                double digitRatio = static_cast<double>(digitCount) / domainPart.length();

                if (digitRatio > 0.5) {
                    score += 50.0;
                }
                else if (digitRatio > 0.3) {
                    score += 30.0;
                }
                else if (digitRatio > 0.15) {
                    score += 15.0;
                }
            }

            // Long sequences of digits
            if (maxConsecutiveDigits >= 6) {
                score += 30.0;
            }
            else if (maxConsecutiveDigits >= 4) {
                score += 15.0;
            }

            // Mixed digits and letters (common in DGA)
            if (hasDigitLetterMix && digitCount >= 2) {
                score += 10.0;
            }

            return std::min(score, 100.0);
        }
        catch (...) {
            return 0.0;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateDistributionUniformity(std::wstring_view domain) const noexcept {
        try {
            // Extract domain name without TLD
            size_t lastDot = domain.find_last_of(L'.');
            std::wstring domainPart = (lastDot != std::wstring::npos)
                ? std::wstring(domain.substr(0, lastDot))
                : std::wstring(domain);

            std::string chars;
            for (wchar_t c : domainPart) {
                if (c != L'.' && c < 128 && std::isalpha(c)) {
                    chars += static_cast<char>(std::tolower(c));
                }
            }

            if (chars.length() < 4) {
                return 0.0;
            }

            // Count character frequencies
            std::array<size_t, 26> counts{};
            for (char c : chars) {
                if (c >= 'a' && c <= 'z') {
                    counts[c - 'a']++;
                }
            }

            // Count unique characters
            size_t uniqueChars = 0;
            for (size_t count : counts) {
                if (count > 0) {
                    uniqueChars++;
                }
            }

            // Calculate expected frequency for uniform distribution
            double expectedFreq = static_cast<double>(chars.length()) / 26.0;

            // Calculate chi-square statistic for uniformity
            double chiSquare = 0.0;
            for (size_t count : counts) {
                double diff = static_cast<double>(count) - expectedFreq;
                chiSquare += (diff * diff) / expectedFreq;
            }

            // DGA domains often have more uniform distributions
            // Normalize chi-square to a score (lower chi-square = more uniform = more suspicious)
            // Typical DGA: chi-square < 50
            // Typical legitimate: chi-square > 100

            // High uniqueness ratio is also suspicious for short domains
            double uniqueRatio = static_cast<double>(uniqueChars) / chars.length();

            double score = 0.0;

            if (chiSquare < 30 && chars.length() >= 8) {
                score += 50.0; // Very uniform - suspicious
            }
            else if (chiSquare < 60) {
                score += 25.0;
            }

            // High unique ratio for the length indicates randomness
            if (uniqueRatio > 0.8 && chars.length() >= 10) {
                score += 30.0;
            }
            else if (uniqueRatio > 0.6 && chars.length() >= 8) {
                score += 15.0;
            }

            return std::min(score, 100.0);
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
            // Extract domain name without TLD
            size_t lastDot = domain.find_last_of(L'.');
            std::wstring domainName = (lastDot != std::wstring::npos)
                ? std::wstring(domain.substr(0, lastDot))
                : std::wstring(domain);

            // Remove any subdomain parts - get second-level domain
            size_t firstDot = domainName.find(L'.');
            if (firstDot != std::wstring::npos) {
                domainName = domainName.substr(firstDot + 1);
            }

            // Skip very short domains
            if (domainName.length() < 4) {
                return 0.0;
            }

            // ================================================================
            // Multi-factor DGA scoring with weighted components
            // ================================================================

            double totalScore = 0.0;
            double totalWeight = 0.0;

            // Factor 1: Shannon entropy (weight: 0.20)
            {
                const double entropy = CalculateDomainEntropy(domainName);
                double entropyScore = 0.0;

                // High entropy (> 4.0) is suspicious
                // Normal English words have entropy around 3.0-3.5
                if (entropy >= 4.5) entropyScore = 100.0;
                else if (entropy >= 4.0) entropyScore = 80.0;
                else if (entropy >= 3.7) entropyScore = 50.0;
                else if (entropy >= 3.5) entropyScore = 25.0;

                totalScore += entropyScore * 0.20;
                totalWeight += 0.20;
            }

            // Factor 2: N-gram analysis (weight: 0.25)
            {
                double ngramScore = CalculateNGramScore(domainName);
                totalScore += ngramScore * 0.25;
                totalWeight += 0.25;
            }

            // Factor 3: Vowel/consonant ratio (weight: 0.15)
            {
                double vcScore = CalculateVowelConsonantScore(domainName);
                totalScore += vcScore * 0.15;
                totalWeight += 0.15;
            }

            // Factor 4: Rare consonant clusters (weight: 0.10)
            {
                double clusterScore = CalculateConsonantClusterScore(domainName);
                totalScore += clusterScore * 0.10;
                totalWeight += 0.10;
            }

            // Factor 5: Numeric patterns (weight: 0.10)
            {
                double numericScore = CalculateNumericPatternScore(domainName);
                totalScore += numericScore * 0.10;
                totalWeight += 0.10;
            }

            // Factor 6: Character distribution uniformity (weight: 0.10)
            {
                double uniformityScore = CalculateDistributionUniformity(domainName);
                totalScore += uniformityScore * 0.10;
                totalWeight += 0.10;
            }

            // Factor 7: Domain length (weight: 0.10)
            {
                double lengthScore = 0.0;
                size_t len = domainName.length();

                // DGA domains are often 8-20 characters
                // Very long domains (> 25) are also suspicious
                if (len >= 15 && len <= 25) {
                    lengthScore = 40.0;
                }
                else if (len > 25) {
                    lengthScore = 60.0;
                }
                else if (len >= 10 && len < 15) {
                    lengthScore = 20.0;
                }

                totalScore += lengthScore * 0.10;
                totalWeight += 0.10;
            }

            // Normalize score
            double finalScore = (totalWeight > 0.0) ? (totalScore / totalWeight) : 0.0;

            return std::min(finalScore, 100.0);
        }
        catch (...) {
            return 0.0;
        }
    }

    // ========================================================================
    // IMPL: DNS TUNNELING DETECTION
    // ========================================================================

    bool NetworkBasedEvasionDetector::Impl::DetectDNSTunneling(
        std::wstring_view domain,
        double& outConfidence,
        std::wstring& outDetails
    ) const noexcept {
        outConfidence = 0.0;
        outDetails.clear();

        try {
            // Count subdomain labels
            size_t labelCount = CountSubdomainLabels(domain);

            // Get longest subdomain label
            std::wstring longestLabel = GetLongestSubdomainLabel(domain);

            // Calculate subdomain entropy
            double subdomainEntropy = CalculateSubdomainEntropy(domain);

            double score = 0.0;

            // Check 1: Excessive subdomain labels
            if (labelCount > MAX_NORMAL_LABEL_COUNT) {
                score += 25.0;
                outDetails += std::format(L"Excessive labels: {} (max normal: {}). ",
                    labelCount, MAX_NORMAL_LABEL_COUNT);
            }

            // Check 2: Long subdomain labels
            if (longestLabel.length() > MAX_NORMAL_SUBDOMAIN_LENGTH) {
                score += 30.0;
                outDetails += std::format(L"Long subdomain label: {} chars. ", longestLabel.length());
            }

            // Check 3: High subdomain entropy
            if (subdomainEntropy > DNS_TUNNEL_ENTROPY_THRESHOLD) {
                score += 25.0;
                outDetails += std::format(L"High subdomain entropy: {:.2f}. ", subdomainEntropy);
            }

            // Check 4: Encoded subdomain patterns
            if (!longestLabel.empty() && IsEncodedSubdomain(longestLabel)) {
                score += 30.0;
                outDetails += L"Base64/Hex encoded subdomain detected. ";
            }

            // Check 5: Very long total domain length
            if (domain.length() > 100) {
                score += 20.0;
                outDetails += std::format(L"Excessive total length: {} chars. ", domain.length());
            }

            outConfidence = std::min(score / 100.0, 1.0);

            return score >= 50.0;
        }
        catch (...) {
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::IsEncodedSubdomain(std::wstring_view subdomain) const noexcept {
        if (subdomain.length() < MIN_TUNNEL_SUBDOMAIN_LENGTH) {
            return false;
        }

        try {
            std::string narrow;
            for (wchar_t c : subdomain) {
                if (c < 128) {
                    narrow += static_cast<char>(c);
                }
            }

            // Check for Base64 pattern: primarily alphanumeric with possible = or + /
            size_t base64Chars = 0;
            size_t hexChars = 0;
            bool hasBase64Special = false;

            for (char c : narrow) {
                if (std::isalnum(c)) {
                    base64Chars++;
                    if (std::isxdigit(c)) {
                        hexChars++;
                    }
                }
                else if (c == '+' || c == '/' || c == '=') {
                    hasBase64Special = true;
                    base64Chars++;
                }
            }

            // High ratio of Base64 characters
            double base64Ratio = static_cast<double>(base64Chars) / narrow.length();
            double hexRatio = static_cast<double>(hexChars) / narrow.length();

            // Pure hex strings (all chars are 0-9, a-f)
            if (hexRatio > 0.95 && narrow.length() >= 16) {
                return true;
            }

            // Base64-like strings
            if (base64Ratio > 0.95 && (hasBase64Special || narrow.length() >= 20)) {
                return true;
            }

            // Check for URL-safe Base64 (uses - and _ instead of + and /)
            size_t urlSafeCount = 0;
            for (char c : narrow) {
                if (std::isalnum(c) || c == '-' || c == '_') {
                    urlSafeCount++;
                }
            }
            if (static_cast<double>(urlSafeCount) / narrow.length() > 0.98 && narrow.length() >= 20) {
                return true;
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateSubdomainEntropy(std::wstring_view domain) const noexcept {
        try {
            // Get the subdomain portion (everything before the second-level domain)
            std::wstring sld = GetSecondLevelDomain(domain);
            if (sld.empty() || sld.length() >= domain.length()) {
                return 0.0;
            }

            // Subdomain is everything before the SLD
            size_t sldPos = domain.find(sld);
            if (sldPos == 0 || sldPos == std::wstring::npos) {
                return 0.0;
            }

            std::wstring subdomain(domain.substr(0, sldPos - 1)); // -1 to remove the dot

            if (subdomain.length() < 3) {
                return 0.0;
            }

            return CalculateDomainEntropy(subdomain);
        }
        catch (...) {
            return 0.0;
        }
    }

    // ========================================================================
    // IMPL: BEACONING DETECTION
    // ========================================================================

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
                if (seconds > 0.0) {
                    intervals.push_back(seconds);
                }
            }

            if (intervals.size() < 2) {
                return 0.0;
            }

            // Sort intervals for percentile analysis
            std::vector<double> sortedIntervals = intervals;
            std::sort(sortedIntervals.begin(), sortedIntervals.end());

            // Use median instead of mean for robustness against outliers
            double median = sortedIntervals[sortedIntervals.size() / 2];

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

            // Calculate jitter percentage
            double jitterPct = CalculateJitterPercentage(intervals);

            // ================================================================
            // Regularity scoring with jitter tolerance
            // ================================================================

            // Perfect beaconing: CV close to 0, jitter < 10%
            // Typical beaconing with jitter: CV < 0.3, jitter < 30%
            // Random traffic: CV > 0.5, jitter > 50%

            double regularity = 0.0;

            // Primary score based on coefficient of variation
            if (cv < 0.05) {
                regularity = 1.0; // Nearly perfect regularity
            }
            else if (cv < 0.10) {
                regularity = 0.95;
            }
            else if (cv < 0.15) {
                regularity = 0.90;
            }
            else if (cv < 0.20) {
                regularity = 0.85;
            }
            else if (cv < 0.30) {
                regularity = 0.75;
            }
            else if (cv < 0.40) {
                regularity = 0.60;
            }
            else if (cv < 0.50) {
                regularity = 0.45;
            }
            else {
                regularity = std::max(0.0, 0.4 - (cv - 0.5) * 0.5);
            }

            // Bonus for low jitter
            if (jitterPct < 10.0) {
                regularity = std::min(1.0, regularity + 0.1);
            }
            else if (jitterPct > 50.0) {
                regularity *= 0.8;
            }

            // Bonus for reasonable beacon interval (common C2 intervals)
            // Common intervals: 1s, 5s, 10s, 30s, 60s, 300s, 600s, 900s, 1800s, 3600s
            const std::vector<double> commonIntervals = { 1, 5, 10, 30, 60, 120, 300, 600, 900, 1800, 3600 };

            bool nearCommonInterval = false;
            for (double common : commonIntervals) {
                if (std::abs(median - common) / common < 0.15) {
                    nearCommonInterval = true;
                    break;
                }
            }

            if (nearCommonInterval && regularity > 0.5) {
                regularity = std::min(1.0, regularity + 0.1);
            }

            return regularity;
        }
        catch (...) {
            return 0.0;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::DetectMultiIntervalBeaconing(
        const std::vector<std::chrono::system_clock::time_point>& timestamps,
        std::vector<double>& detectedIntervals
    ) const noexcept {
        detectedIntervals.clear();

        if (timestamps.size() < 10) {
            return false;
        }

        try {
            // Calculate all intervals
            std::vector<double> intervals;
            for (size_t i = 1; i < timestamps.size(); ++i) {
                double seconds = std::chrono::duration<double>(timestamps[i] - timestamps[i - 1]).count();
                if (seconds > 0.5) { // Ignore very short intervals
                    intervals.push_back(seconds);
                }
            }

            if (intervals.size() < 5) {
                return false;
            }

            // Cluster intervals using a simple histogram approach
            std::map<int, size_t> buckets;
            for (double interval : intervals) {
                // Round to nearest 5 seconds for bucketing
                int bucket = static_cast<int>(std::round(interval / 5.0) * 5);
                buckets[bucket]++;
            }

            // Find dominant intervals (appearing more than 20% of time)
            const double threshold = intervals.size() * 0.15;

            for (const auto& [bucket, count] : buckets) {
                if (count >= threshold && bucket > 0) {
                    detectedIntervals.push_back(static_cast<double>(bucket));
                }
            }

            // Multi-interval beaconing: 2-3 distinct common intervals
            return detectedIntervals.size() >= 2 && detectedIntervals.size() <= 4;
        }
        catch (...) {
            return false;
        }
    }

    double NetworkBasedEvasionDetector::Impl::CalculateJitterPercentage(
        const std::vector<double>& intervals
    ) const noexcept {
        if (intervals.size() < 2) {
            return 100.0;
        }

        try {
            double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();

            if (mean <= 0.0) {
                return 100.0;
            }

            // Calculate max deviation from mean
            double maxDeviation = 0.0;
            for (double interval : intervals) {
                double deviation = std::abs(interval - mean);
                maxDeviation = std::max(maxDeviation, deviation);
            }

            return (maxDeviation / mean) * 100.0;
        }
        catch (...) {
            return 100.0;
        }
    }

    // ========================================================================
    // IMPL: NETWORK ADAPTER ANALYSIS
    // ========================================================================

    bool NetworkBasedEvasionDetector::Impl::CheckNetworkAdapters(
        bool& outVpnDetected,
        std::wstring& outVpnName,
        bool& outVmMacDetected,
        std::wstring& outVmMacInfo,
        std::vector<std::wstring>& outAdapterDetails,
        NetworkEvasionError* err
    ) const noexcept {
        outVpnDetected = false;
        outVmMacDetected = false;
        outAdapterDetails.clear();

        ULONG family = AF_UNSPEC;
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
        ULONG bufferSize = 15000;

        // Allocate buffer
        std::vector<BYTE> buffer(bufferSize);
        PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

        // First call to get size
        DWORD result = GetAdaptersAddresses(family, flags, nullptr, pAddresses, &bufferSize);

        if (result == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(bufferSize);
            pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
            result = GetAdaptersAddresses(family, flags, nullptr, pAddresses, &bufferSize);
        }

        if (result != ERROR_SUCCESS) {
            if (err) {
                err->win32Code = result;
                err->message = L"GetAdaptersAddresses failed";
            }
            return false;
        }

        // VPN detection keywords
        const std::vector<std::wstring> vpnKeywords = {
            L"VPN", L"TAP", L"TUN", L"Virtual", L"OpenVPN", L"WireGuard",
            L"NordVPN", L"ExpressVPN", L"Cisco AnyConnect", L"Fortinet",
            L"Juniper", L"GlobalProtect", L"Pulse Secure", L"SoftEther",
            L"ProtonVPN", L"Surfshark", L"CyberGhost", L"IPVanish",
            L"TunnelBear", L"Windscribe", L"ZeroTier", L"Hamachi",
            L"PPTP", L"L2TP", L"IKEv2", L"SSTP", L"Cloudflare WARP"
        };

        // VM MAC OUI prefixes (Organizationally Unique Identifiers)
        struct MacOui {
            uint8_t bytes[3];
            const wchar_t* vendor;
        };

        const std::vector<MacOui> vmMacOuis = {
            // VMware
            {{0x00, 0x05, 0x69}, L"VMware"},
            {{0x00, 0x0C, 0x29}, L"VMware"},
            {{0x00, 0x1C, 0x14}, L"VMware"},
            {{0x00, 0x50, 0x56}, L"VMware"},
            // VirtualBox
            {{0x08, 0x00, 0x27}, L"VirtualBox"},
            {{0x0A, 0x00, 0x27}, L"Hybrid Analysis/VirtualBox"},
            // Parallels
            {{0x00, 0x1C, 0x42}, L"Parallels"},
            // Xen
            {{0x00, 0x16, 0x3E}, L"Xen"},
            // QEMU/KVM
            {{0x52, 0x54, 0x00}, L"QEMU/KVM"},
            // Hyper-V
            {{0x00, 0x15, 0x5D}, L"Hyper-V"},
            // Microsoft Virtual PC
            {{0x00, 0x03, 0xFF}, L"Microsoft Virtual PC"},
            // AWS EC2
            {{0x02, 0x42, 0xAC}, L"Docker"},
            // Google Cloud
            {{0x42, 0x01, 0x0A}, L"Google Cloud"}
        };

        // Iterate adapters
        for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
            pCurrAddresses != nullptr;
            pCurrAddresses = pCurrAddresses->Next) {

            // Skip non-operational adapters
            if (pCurrAddresses->OperStatus != IfOperStatusUp) continue;

            std::wstring description = pCurrAddresses->Description ? pCurrAddresses->Description : L"";
            std::wstring friendlyName = pCurrAddresses->FriendlyName ? pCurrAddresses->FriendlyName : L"";
            std::wstring dnsSuffix = pCurrAddresses->DnsSuffix ? pCurrAddresses->DnsSuffix : L"";

            // Build adapter info
            std::wstringstream adapterInfo;
            adapterInfo << L"[" << friendlyName << L"] " << description;

            // 1. VPN Detection
            for (const auto& keyword : vpnKeywords) {
                if (Utils::StringUtils::IContains(description, keyword) ||
                    Utils::StringUtils::IContains(friendlyName, keyword)) {
                    outVpnDetected = true;
                    outVpnName = description.empty() ? friendlyName : description;
                    adapterInfo << L" [VPN]";
                    break;
                }
            }

            // Also check adapter type
            if (pCurrAddresses->IfType == IF_TYPE_TUNNEL ||
                pCurrAddresses->IfType == IF_TYPE_PPP) {
                if (!outVpnDetected) {
                    outVpnDetected = true;
                    outVpnName = description.empty() ? friendlyName : description;
                    adapterInfo << L" [Tunnel/PPP]";
                }
            }

            // 2. MAC Address OUI Fingerprinting (VM Detection)
            if (pCurrAddresses->PhysicalAddressLength >= 3) {
                const BYTE* mac = pCurrAddresses->PhysicalAddress;

                for (const auto& oui : vmMacOuis) {
                    if (mac[0] == oui.bytes[0] &&
                        mac[1] == oui.bytes[1] &&
                        mac[2] == oui.bytes[2]) {

                        outVmMacDetected = true;
                        std::wstringstream ss;
                        ss << oui.vendor << L" OUI (";
                        ss << std::hex << std::setfill(L'0');
                        ss << std::setw(2) << static_cast<int>(mac[0]) << L"-";
                        ss << std::setw(2) << static_cast<int>(mac[1]) << L"-";
                        ss << std::setw(2) << static_cast<int>(mac[2]);
                        ss << L")";
                        outVmMacInfo = ss.str();
                        adapterInfo << L" [VM: " << oui.vendor << L"]";
                        break;
                    }
                }

                // Add MAC to adapter info
                adapterInfo << L" MAC:";
                for (ULONG i = 0; i < pCurrAddresses->PhysicalAddressLength && i < 6; ++i) {
                    if (i > 0) adapterInfo << L"-";
                    adapterInfo << std::hex << std::setfill(L'0') << std::setw(2)
                        << static_cast<int>(mac[i]);
                }
            }

            outAdapterDetails.push_back(adapterInfo.str());
        }

        return true;
    }

    bool NetworkBasedEvasionDetector::Impl::DetectSandboxNetwork(
        std::wstring& outDetails
    ) const noexcept {
        outDetails.clear();

        try {
            // Check for sandbox-specific network characteristics

            // 1. Check for common sandbox IP ranges
            std::vector<Utils::NetworkUtils::IpAddress> googleIps;
            if (Utils::NetworkUtils::ResolveHostname(L"google.com", googleIps)) {
                // Sandboxes sometimes return specific IPs or fail resolution
                if (googleIps.empty()) {
                    outDetails += L"DNS resolution returns no results. ";
                    return true;
                }
            }
            else {
                outDetails += L"DNS resolution failed for google.com. ";
                return true;
            }

            // 2. Check network adapter count and types
            bool vpnDetected, vmMacDetected;
            std::wstring vpnName, vmMacInfo;
            std::vector<std::wstring> adapterDetails;

            CheckNetworkAdapters(vpnDetected, vpnName, vmMacDetected, vmMacInfo, adapterDetails, nullptr);

            // Very few adapters might indicate sandbox
            if (adapterDetails.size() <= 1) {
                outDetails += L"Only single network adapter present. ";
                return true;
            }

            // 3. Check for specific sandbox indicators
            for (const auto& adapter : adapterDetails) {
                std::wstring lowerAdapter = adapter;
                std::transform(lowerAdapter.begin(), lowerAdapter.end(),
                    lowerAdapter.begin(), ::towlower);

                // Check for sandbox-specific adapter names
                if (lowerAdapter.find(L"sandbox") != std::wstring::npos ||
                    lowerAdapter.find(L"cuckoo") != std::wstring::npos ||
                    lowerAdapter.find(L"anyrun") != std::wstring::npos ||
                    lowerAdapter.find(L"hybrid analysis") != std::wstring::npos ||
                    lowerAdapter.find(L"joe sandbox") != std::wstring::npos) {
                    outDetails += L"Sandbox-specific adapter detected: " + adapter + L". ";
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: NETWORK CAPTURE TOOL DETECTION
    // ========================================================================

    bool NetworkBasedEvasionDetector::Impl::DetectNetworkCaptureTools(
        std::vector<std::wstring>& detectedTools
    ) const noexcept {
        detectedTools.clear();

        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return false;
            }

            PROCESSENTRY32W pe32 = {};
            pe32.dwSize = sizeof(pe32);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    std::wstring processName = pe32.szExeFile;
                    std::wstring lowerName = processName;
                    std::transform(lowerName.begin(), lowerName.end(),
                        lowerName.begin(), ::towlower);

                    for (const auto& tool : NETWORK_CAPTURE_TOOLS) {
                        if (lowerName == tool) {
                            detectedTools.push_back(processName);
                            break;
                        }
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);

            if (!detectedTools.empty()) {
                // Use atomic operation - can't use ++ on const atomic
                m_stats.totalDetections.fetch_add(1, std::memory_order_relaxed);
            }

            return !detectedTools.empty();
        }
        catch (...) {
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::DetectPromiscuousMode() const noexcept {
        // ============================================================================
        // Enterprise-grade promiscuous mode detection for network interface cards
        // Malware analysis tools and network sniffers often put NICs in promiscuous mode
        // This function detects such behavior which may indicate sandbox/analysis environment
        // ============================================================================
        
        try {
            // Allocate buffer for adapter information
            ULONG bufferSize = 0;
            DWORD result = ::GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                nullptr,
                nullptr,
                &bufferSize
            );
            
            if (result != ERROR_BUFFER_OVERFLOW || bufferSize == 0) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"GetAdaptersAddresses initial call failed with code: %lu", result);
                return false;
            }
            
            // Cap allocation to prevent memory exhaustion attacks
            constexpr ULONG MAX_ADAPTER_BUFFER = 64 * 1024; // 64 KB max
            if (bufferSize > MAX_ADAPTER_BUFFER) {
                SS_LOG_WARN(LOG_CATEGORY, L"Adapter buffer size exceeds limit: %lu > %lu", 
                    bufferSize, MAX_ADAPTER_BUFFER);
                return false;
            }
            
            // RAII buffer allocation
            auto adapterBuffer = std::make_unique<uint8_t[]>(bufferSize);
            auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuffer.get());
            
            result = ::GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                nullptr,
                adapters,
                &bufferSize
            );
            
            if (result != ERROR_SUCCESS) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"GetAdaptersAddresses failed with code: %lu", result);
                return false;
            }
            
            // Track promiscuous interfaces found
            bool promiscuousFound = false;
            std::vector<std::wstring> promiscuousAdapters;
            
            // NDIS packet filter constants (defined locally to avoid header dependencies)
            constexpr ULONG LOCAL_NDIS_PACKET_TYPE_PROMISCUOUS = 0x00000020;
            constexpr ULONG LOCAL_NDIS_PACKET_TYPE_ALL_LOCAL = 0x00000080;
            // IOCTL for querying NDIS global statistics (hardcoded to avoid CTL_CODE macro issues)
            constexpr DWORD LOCAL_IOCTL_NDIS_QUERY_GLOBAL_STATS = 0x00170002;
            // OID for packet filter query
            constexpr ULONG LOCAL_OID_GEN_CURRENT_PACKET_FILTER = 0x0001010E;
            
            // Iterate through all adapters
            for (PIP_ADAPTER_ADDRESSES adapter = adapters; 
                 adapter != nullptr; 
                 adapter = adapter->Next) {
                
                // Skip loopback and tunnel adapters - not relevant for sniffing
                if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
                    adapter->IfType == IF_TYPE_TUNNEL) {
                    continue;
                }
                
                // Skip adapters that are not operational
                if (adapter->OperStatus != IfOperStatusUp) {
                    continue;
                }
                
                // Method 1: Query MIB_IF_ROW2 for packet statistics analysis
                MIB_IF_ROW2 ifRow = {};
                ifRow.InterfaceLuid = adapter->Luid;
                
                DWORD mibResult = ::GetIfEntry2(&ifRow);
                if (mibResult == NO_ERROR) {
                    // Check if incoming packets >> outgoing (typical of passive sniffing)
                    if (ifRow.InUcastPkts > 0 && ifRow.OutUcastPkts > 0) {
                        double inOutRatio = static_cast<double>(ifRow.InUcastPkts) / 
                                           static_cast<double>(ifRow.OutUcastPkts);
                        
                        // Extremely high ratio might indicate passive capture
                        // Normal ratio is typically < 10:1, sniffers can be 100:1+
                        if (inOutRatio > 50.0 && ifRow.InUcastPkts > 100000) {
                            SS_LOG_INFO(LOG_CATEGORY,
                                L"High in/out packet ratio on %ls: %.2f:1 (%llu in, %llu out)",
                                adapter->FriendlyName ? adapter->FriendlyName : L"Unknown",
                                inOutRatio, ifRow.InUcastPkts, ifRow.OutUcastPkts);
                        }
                    }
                }
                
                // Method 2: Check via NDIS OID query using DeviceIoControl
                // This requires admin privileges but we're an EDR so we have them
                
                // Build the device path for the adapter
                if (adapter->AdapterName == nullptr) {
                    continue; // Can't query without adapter name
                }
                
                // AdapterName is GUID format like {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
                std::string guidStr(adapter->AdapterName);
                std::wstring guidWide(guidStr.begin(), guidStr.end());
                std::wstring devicePath = L"\\\\.\\NDIS_" + guidWide;
                
                // Open handle to the NDIS device
                HANDLE hDevice = ::CreateFileW(
                    devicePath.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr
                );
                
                if (hDevice != INVALID_HANDLE_VALUE) {
                    // Query OID_GEN_CURRENT_PACKET_FILTER
                    ULONG oidQuery = LOCAL_OID_GEN_CURRENT_PACKET_FILTER;
                    ULONG packetFilter = 0;
                    DWORD bytesReturned = 0;
                    
                    if (::DeviceIoControl(
                            hDevice,
                            LOCAL_IOCTL_NDIS_QUERY_GLOBAL_STATS,
                            &oidQuery,
                            sizeof(oidQuery),
                            &packetFilter,
                            sizeof(packetFilter),
                            &bytesReturned,
                            nullptr)) {
                        
                        if (bytesReturned >= sizeof(ULONG)) {
                            // Check for promiscuous mode flags
                            if (packetFilter & LOCAL_NDIS_PACKET_TYPE_PROMISCUOUS) {
                                promiscuousFound = true;
                                promiscuousAdapters.push_back(
                                    adapter->FriendlyName ? adapter->FriendlyName : L"Unknown"
                                );
                                
                                SS_LOG_WARN(LOG_CATEGORY,
                                    L"Promiscuous mode detected on adapter: %ls (filter: 0x%08X)",
                                    adapter->FriendlyName ? adapter->FriendlyName : L"Unknown",
                                    packetFilter);
                            }
                            else if (packetFilter & LOCAL_NDIS_PACKET_TYPE_ALL_LOCAL) {
                                // ALL_LOCAL is less suspicious but still worth noting
                                SS_LOG_DEBUG(LOG_CATEGORY,
                                    L"ALL_LOCAL packet filter on adapter: %ls (filter: 0x%08X)",
                                    adapter->FriendlyName ? adapter->FriendlyName : L"Unknown",
                                    packetFilter);
                            }
                        }
                    }
                    
                    ::CloseHandle(hDevice);
                }
                
            } // End adapter loop
            
            // Method 3: Check for packet capture driver presence (system-wide check, do once)
            static bool driversChecked = false;
            static bool captureDriversFound = false;
            
            if (!driversChecked) {
                driversChecked = true;
                
                // Check for WinPcap/Npcap service
                SC_HANDLE hSCManager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
                if (hSCManager != nullptr) {
                    const wchar_t* captureServices[] = {
                        L"npf",      // WinPcap/Npcap driver
                        L"npcap",    // Npcap service
                        L"NPF",      // Legacy WinPcap
                    };
                    
                    for (const auto* serviceName : captureServices) {
                        SC_HANDLE hService = ::OpenServiceW(hSCManager, serviceName, SERVICE_QUERY_STATUS);
                        if (hService != nullptr) {
                            SERVICE_STATUS status = {};
                            if (::QueryServiceStatus(hService, &status)) {
                                if (status.dwCurrentState == SERVICE_RUNNING) {
                                    captureDriversFound = true;
                                    SS_LOG_INFO(LOG_CATEGORY,
                                        L"Packet capture driver running: %ls", serviceName);
                                }
                            }
                            ::CloseServiceHandle(hService);
                        }
                    }
                    ::CloseServiceHandle(hSCManager);
                }
                
                // Check for NPF device directly
                HANDLE hNpf = ::CreateFileW(
                    L"\\\\.\\NPF",
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr
                );
                if (hNpf != INVALID_HANDLE_VALUE) {
                    captureDriversFound = true;
                    ::CloseHandle(hNpf);
                    SS_LOG_INFO(LOG_CATEGORY,
                        L"NPF device accessible - packet capture infrastructure present");
                }
            }
            
            // Combine results: promiscuous mode OR capture drivers indicate potential monitoring
            if (promiscuousFound) {
                m_stats.totalDetections.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Network monitoring detected: %zu adapter(s) in promiscuous mode",
                    promiscuousAdapters.size());
                return true;
            }
            
            // Capture drivers alone are not definitive (many legitimate uses)
            // but combined with other evasion signals could be significant
            
            return false;
            
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception in DetectPromiscuousMode: %hs", e.what());
            return false;
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Unknown exception in DetectPromiscuousMode");
            return false;
        }
    }

    // ========================================================================
    // IMPL: C2 INFRASTRUCTURE DETECTION
    // ========================================================================

    bool NetworkBasedEvasionDetector::Impl::IsDynamicDNSDomain(std::wstring_view domain) const noexcept {
        try {
            std::wstring lowerDomain(domain);
            std::transform(lowerDomain.begin(), lowerDomain.end(),
                lowerDomain.begin(), ::towlower);

            for (const auto& ddns : DDNS_PROVIDERS) {
                if (lowerDomain.find(ddns) != std::wstring::npos) {
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::HasSuspiciousTLD(std::wstring_view domain) const noexcept {
        try {
            std::wstring tld = GetTLD(domain);
            if (tld.empty()) {
                return false;
            }

            std::transform(tld.begin(), tld.end(), tld.begin(), ::towlower);

            for (const auto& suspiciousTld : SUSPICIOUS_TLDS) {
                if (tld == suspiciousTld) {
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::IsCloudProviderDomain(std::wstring_view domain) const noexcept {
        try {
            std::wstring lowerDomain(domain);
            std::transform(lowerDomain.begin(), lowerDomain.end(),
                lowerDomain.begin(), ::towlower);

            for (const auto& provider : CLOUD_PROVIDERS) {
                if (lowerDomain.find(provider) != std::wstring::npos) {
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::CheckSSLCertificate(
        std::wstring_view domain,
        bool& outSelfSigned,
        bool& outExpired,
        bool& outMismatch,
        std::wstring& outDetails
    ) const noexcept {
        // ============================================================================
        // Enterprise-grade SSL/TLS certificate validation
        // Detects suspicious certificates commonly used by:
        //   - C2 infrastructure (self-signed, expired, mismatched)
        //   - MITM attacks (interception proxies)
        //   - Malware callbacks (cheap/free certs, DV-only)
        //   - Analysis environments (lab-generated certs)
        // ============================================================================
        
        outSelfSigned = false;
        outExpired = false;
        outMismatch = false;
        outDetails.clear();

        try {
            // Input validation
            if (domain.empty() || domain.length() > 253) {
                outDetails = L"Invalid domain name";
                return false;
            }
            
            Utils::NetworkUtils::SslCertificateInfo certInfo;
            // GetSslCertificate requires hostname, port, and certInfo
            if (!Utils::NetworkUtils::GetSslCertificate(domain, 443, certInfo)) {
                outDetails = L"Failed to retrieve SSL certificate - connection failed or no TLS";
                return false;
            }

            // Track all suspicious indicators for comprehensive reporting
            std::vector<std::wstring> issues;
            int suspicionScore = 0; // Cumulative score for severity assessment
            
            // ====================================================================
            // CHECK 1: Self-signed certificate detection
            // ====================================================================
            if (certInfo.isSelfSigned || certInfo.issuer == certInfo.subject) {
                outSelfSigned = true;
                issues.push_back(L"Self-signed certificate");
                suspicionScore += 40; // High suspicion
            }

            // ====================================================================
            // CHECK 2: Certificate temporal validity
            // ====================================================================
            auto now = std::chrono::system_clock::now();
            
            if (now > certInfo.validTo) {
                outExpired = true;
                
                // Calculate how long expired
                auto expiredDuration = std::chrono::duration_cast<std::chrono::hours>(now - certInfo.validTo);
                int daysExpired = static_cast<int>(expiredDuration.count() / 24);
                
                issues.push_back(std::format(L"Certificate expired ({} days ago)", daysExpired));
                
                // Score based on severity - recently expired might be negligence, long expired is suspicious
                if (daysExpired > 365) {
                    suspicionScore += 50; // Very suspicious - over a year expired
                } else if (daysExpired > 90) {
                    suspicionScore += 35;
                } else if (daysExpired > 30) {
                    suspicionScore += 25;
                } else {
                    suspicionScore += 15; // Recently expired - might be admin oversight
                }
            }
            else if (now < certInfo.validFrom) {
                // Certificate not yet valid - even more suspicious than expired
                auto notYetDuration = std::chrono::duration_cast<std::chrono::hours>(certInfo.validFrom - now);
                int daysUntilValid = static_cast<int>(notYetDuration.count() / 24);
                
                issues.push_back(std::format(L"Certificate not yet valid (valid in {} days)", daysUntilValid));
                suspicionScore += 45; // Very suspicious - indicates intentional manipulation
            }
            
            // ====================================================================
            // CHECK 3: Certificate validity period analysis
            // ====================================================================
            auto validityPeriod = std::chrono::duration_cast<std::chrono::hours>(certInfo.validTo - certInfo.validFrom);
            int validityDays = static_cast<int>(validityPeriod.count() / 24);
            
            // Extremely short validity (< 30 days) is suspicious - might be temporary C2 infra
            if (validityDays < 30 && validityDays > 0) {
                issues.push_back(std::format(L"Very short validity period ({} days)", validityDays));
                suspicionScore += 25;
            }
            // Extremely long validity (> 825 days / ~27 months) violates CA/Browser Forum rules
            // Legitimate CAs since 2020 max out at 398 days (13 months)
            else if (validityDays > 825) {
                issues.push_back(std::format(L"Excessive validity period ({} days) - likely self-generated", validityDays));
                suspicionScore += 20;
            }
            // > 398 days (current max for public CAs since Sept 2020)
            else if (validityDays > 398 && !outSelfSigned) {
                issues.push_back(std::format(L"Validity period ({} days) exceeds CA/Browser Forum maximum", validityDays));
                suspicionScore += 10; // Moderate - might be older cert or internal CA
            }

            // ====================================================================
            // CHECK 4: Subject name matching (RFC 6125 compliant)
            // ====================================================================
            std::wstring domainLower(domain);
            std::transform(domainLower.begin(), domainLower.end(), domainLower.begin(), ::towlower);
            
            bool nameMatches = false;
            
            // Check Subject Common Name (CN) - deprecated but still used
            std::wstring subjectLower = certInfo.subject;
            std::transform(subjectLower.begin(), subjectLower.end(), subjectLower.begin(), ::towlower);
            
            // Extract CN from subject string (format: "CN=..., O=..., C=...")
            size_t cnPos = subjectLower.find(L"cn=");
            if (cnPos != std::wstring::npos) {
                size_t cnEnd = subjectLower.find(L',', cnPos);
                std::wstring cn = (cnEnd != std::wstring::npos) 
                    ? subjectLower.substr(cnPos + 3, cnEnd - cnPos - 3)
                    : subjectLower.substr(cnPos + 3);
                
                // Trim whitespace
                while (!cn.empty() && std::iswspace(cn.front())) cn.erase(0, 1);
                while (!cn.empty() && std::iswspace(cn.back())) cn.pop_back();
                
                // Check exact match or wildcard
                if (cn == domainLower) {
                    nameMatches = true;
                }
                else if (cn.length() > 2 && cn.substr(0, 2) == L"*.") {
                    std::wstring wildcardBase = cn.substr(2);
                    size_t dotPos = domainLower.find(L'.');
                    if (dotPos != std::wstring::npos && domainLower.substr(dotPos + 1) == wildcardBase) {
                        nameMatches = true;
                    }
                }
            }
            
            // Check Subject Alternative Names (preferred method per RFC 6125)
            for (const auto& san : certInfo.subjectAltNames) {
                if (nameMatches) break;
                
                std::wstring sanLower = san;
                std::transform(sanLower.begin(), sanLower.end(), sanLower.begin(), ::towlower);

                // Exact match
                if (sanLower == domainLower) {
                    nameMatches = true;
                    break;
                }
                
                // Wildcard match (RFC 6125 Section 6.4.3)
                if (sanLower.length() > 2 && sanLower.substr(0, 2) == L"*.") {
                    std::wstring wildcardBase = sanLower.substr(2);
                    size_t dotPos = domainLower.find(L'.');
                    if (dotPos != std::wstring::npos) {
                        // Wildcard only matches single label
                        // *.example.com matches www.example.com but NOT www.sub.example.com
                        std::wstring afterFirstDot = domainLower.substr(dotPos + 1);
                        if (afterFirstDot == wildcardBase) {
                            // Ensure the wildcard is not matching a multi-level subdomain
                            size_t wildcardDots = std::count(domainLower.begin(), domainLower.begin() + dotPos, L'.');
                            if (wildcardDots == 0) {
                                nameMatches = true;
                                break;
                            }
                        }
                    }
                }
                
                // IP address SAN match (for IP-based domains)
                // Format: "IP:x.x.x.x" or just IP address
                if (sanLower.find(L"ip:") == 0) {
                    std::wstring sanIp = sanLower.substr(3);
                    if (sanIp == domainLower) {
                        nameMatches = true;
                        break;
                    }
                }
            }

            if (!nameMatches) {
                outMismatch = true;
                issues.push_back(L"Certificate name mismatch (CN/SAN doesn't match domain)");
                suspicionScore += 30;
            }

            // ====================================================================
            // CHECK 5: Issuer analysis for suspicious CAs
            // ====================================================================
            std::wstring issuerLower = certInfo.issuer;
            std::transform(issuerLower.begin(), issuerLower.end(), issuerLower.begin(), ::towlower);
            
            // Known suspicious/revoked/low-trust CAs
            static const std::vector<std::wstring> SUSPICIOUS_ISSUERS = {
                L"symantec",           // Distrusted since 2018
                L"thawte",             // Subsidiary of distrusted Symantec
                L"verisign class 3",   // Older Symantec subsidiary
                L"geotrust",           // Symantec subsidiary
                L"rapidssl",           // Symantec subsidiary
                L"startcom",           // Distrusted since 2016
                L"wosign",             // Distrusted since 2016
                L"certum",             // History of misissued certs
                L"camerfirma",         // Compliance issues
                // Known test/dev CAs that shouldn't be in production
                L"localhost",
                L"test",
                L"development",
                L"debug",
                L"untrusted",
                L"invalid",
                L"example",
                L"fiddler",            // HTTP debugger
                L"charles",            // Charles Proxy
                L"burp",               // Burp Suite
                L"mitmproxy",          // MITM proxy
                L"zscaler",            // SSL inspection (legitimate but indicates interception)
            };
            
            for (const auto& suspicious : SUSPICIOUS_ISSUERS) {
                if (issuerLower.find(suspicious) != std::wstring::npos) {
                    issues.push_back(std::format(L"Suspicious issuer detected: {}", suspicious));
                    
                    // Score differently for distrusted vs interception
                    if (suspicious == L"fiddler" || suspicious == L"charles" || 
                        suspicious == L"burp" || suspicious == L"mitmproxy") {
                        suspicionScore += 50; // Very suspicious - active interception
                    } else if (suspicious == L"zscaler") {
                        suspicionScore += 5; // Low - might be legitimate enterprise
                    } else {
                        suspicionScore += 25;
                    }
                    break;
                }
            }

            // ====================================================================
            // CHECK 6: Free/DV certificate detection (higher C2 correlation)
            // ====================================================================
            // These issuers offer free certificates commonly abused by malware
            static const std::vector<std::wstring> FREE_DV_ISSUERS = {
                L"let's encrypt",
                L"letsencrypt",
                L"zerossl",
                L"buypass",
                L"ssl.com",
            };
            
            bool isFreeCert = false;
            for (const auto& freeIssuer : FREE_DV_ISSUERS) {
                if (issuerLower.find(freeIssuer) != std::wstring::npos) {
                    isFreeCert = true;
                    break;
                }
            }
            
            // Free certs alone aren't suspicious, but combined with other indicators...
            if (isFreeCert && (outSelfSigned || outExpired || outMismatch)) {
                issues.push_back(L"Free/DV certificate with other issues - higher C2 likelihood");
                suspicionScore += 15;
            }

            // ====================================================================
            // CHECK 7: Serial number analysis
            // ====================================================================
            if (!certInfo.serialNumber.empty()) {
                // Check for common test serial numbers
                if (certInfo.serialNumber == L"00" || 
                    certInfo.serialNumber == L"01" ||
                    certInfo.serialNumber == L"1" ||
                    certInfo.serialNumber.length() < 4) {
                    issues.push_back(L"Suspicious serial number (too short/simple)");
                    suspicionScore += 20;
                }
                
                // Check for sequential or all-same digit serials
                bool allSame = true;
                for (size_t i = 1; i < certInfo.serialNumber.length() && allSame; ++i) {
                    if (certInfo.serialNumber[i] != certInfo.serialNumber[0]) {
                        allSame = false;
                    }
                }
                if (allSame && certInfo.serialNumber.length() > 3) {
                    issues.push_back(L"Suspicious serial number (all same digits)");
                    suspicionScore += 15;
                }
            }

            // ====================================================================
            // CHECK 8: Subject organization analysis
            // ====================================================================
            // Missing organization in certificate - DV certs don't require it but OV/EV do
            bool hasOrganization = (subjectLower.find(L"o=") != std::wstring::npos);
            
            // High-value domains without organization cert are suspicious
            static const std::vector<std::wstring> HIGH_VALUE_TLDS = {
                L".bank", L".gov", L".mil", L".edu"
            };
            
            for (const auto& tld : HIGH_VALUE_TLDS) {
                if (domainLower.length() > tld.length() &&
                    domainLower.substr(domainLower.length() - tld.length()) == tld) {
                    if (!hasOrganization && !outSelfSigned) {
                        issues.push_back(std::format(L"High-value domain ({}) without OV/EV certificate", tld));
                        suspicionScore += 25;
                    }
                    break;
                }
            }

            // ====================================================================
            // CHECK 9: Recently issued certificate analysis
            // ====================================================================
            auto certAge = std::chrono::duration_cast<std::chrono::hours>(now - certInfo.validFrom);
            int certAgeDays = static_cast<int>(certAge.count() / 24);
            
            // Certificate issued very recently AND combined with other issues
            if (certAgeDays < 7 && suspicionScore > 0) {
                issues.push_back(std::format(L"Very recently issued certificate ({} days old) with other issues", certAgeDays));
                suspicionScore += 10;
            }

            // ====================================================================
            // BUILD OUTPUT DETAILS
            // ====================================================================
            if (!issues.empty()) {
                outDetails = L"SSL Issues: ";
                for (size_t i = 0; i < issues.size(); ++i) {
                    if (i > 0) outDetails += L"; ";
                    outDetails += issues[i];
                }
                outDetails += std::format(L" [Suspicion Score: {}]", suspicionScore);
                
                // Log if highly suspicious
                if (suspicionScore >= 50) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Highly suspicious SSL certificate for %.*ls: %ls", 
                        static_cast<int>(domain.length()), domain.data(), outDetails.c_str());
                }
            }
            
            // Store suspicion metrics for analysis
            if (suspicionScore > 0) {
                m_stats.totalDetections.fetch_add(1, std::memory_order_relaxed);
            }

            return true;
            
        } catch (const std::exception& e) {
            outDetails = std::format(L"Certificate check failed: {}",
                Utils::StringUtils::ToWide(e.what()));
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Exception in CheckSSLCertificate for %.*ls: %ls", 
                static_cast<int>(domain.length()), domain.data(), outDetails.c_str());
            return false;
        } catch (...) {
            outDetails = L"Certificate check failed: unknown exception";
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Unknown exception in CheckSSLCertificate for %.*ls", 
                static_cast<int>(domain.length()), domain.data());
            return false;
        }
    }

    bool NetworkBasedEvasionDetector::Impl::DetectDomainFronting(
        std::wstring_view requestedHost,
        std::wstring_view sniHost,
        std::wstring& outDetails
    ) const noexcept {
        outDetails.clear();

        if (requestedHost.empty() || sniHost.empty()) {
            return false;
        }

        try {
            // Domain fronting: SNI and Host header don't match
            std::wstring lowerRequested(requestedHost);
            std::wstring lowerSni(sniHost);
            std::transform(lowerRequested.begin(), lowerRequested.end(),
                lowerRequested.begin(), ::towlower);
            std::transform(lowerSni.begin(), lowerSni.end(),
                lowerSni.begin(), ::towlower);

            if (lowerRequested != lowerSni) {
                // Check if they share same parent domain (legitimate CDN usage)
                std::wstring requestedSld = GetSecondLevelDomain(lowerRequested);
                std::wstring sniSld = GetSecondLevelDomain(lowerSni);

                if (requestedSld != sniSld) {
                    outDetails = std::format(L"Domain fronting detected: SNI={}, Host={}",
                        sniHost, requestedHost);
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: VALIDATION HELPERS
    // ========================================================================

    bool NetworkBasedEvasionDetector::Impl::IsValidDomain(std::wstring_view domain) const noexcept {
        if (domain.empty() || domain.length() > 253) {
            return false;
        }

        // Check for valid characters and structure
        bool hasDot = false;
        bool lastWasDot = false;
        size_t labelLength = 0;

        for (wchar_t c : domain) {
            if (c == L'.') {
                if (lastWasDot || labelLength == 0) {
                    return false; // Consecutive dots or empty label
                }
                if (labelLength > 63) {
                    return false; // Label too long
                }
                hasDot = true;
                lastWasDot = true;
                labelLength = 0;
            }
            else if (std::iswalnum(c) || c == L'-') {
                lastWasDot = false;
                labelLength++;
            }
            else {
                return false; // Invalid character
            }
        }

        // Check last label
        if (labelLength == 0 || labelLength > 63) {
            return false;
        }

        return hasDot;
    }

    bool NetworkBasedEvasionDetector::Impl::IsValidIPv4(std::wstring_view ip) const noexcept {
        if (ip.empty()) {
            return false;
        }

        try {
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

                // Check for leading zeros (except for "0" itself)
                if (octet.length() > 1 && octet[0] == L'0') {
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
        std::wstring lowerDomain(domain);
        std::transform(lowerDomain.begin(), lowerDomain.end(),
            lowerDomain.begin(), ::towlower);

        for (const auto& checkDomain : NetworkEvasionConstants::CONNECTIVITY_CHECK_DOMAINS) {
            if (lowerDomain.find(checkDomain) != std::wstring::npos) {
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

    std::wstring NetworkBasedEvasionDetector::Impl::GetSecondLevelDomain(std::wstring_view domain) const noexcept {
        try {
            // Find last dot
            size_t lastDot = domain.find_last_of(L'.');
            if (lastDot == std::wstring::npos) {
                return std::wstring(domain);
            }

            // Find second-to-last dot
            size_t secondLastDot = domain.find_last_of(L'.', lastDot - 1);
            if (secondLastDot == std::wstring::npos) {
                return std::wstring(domain);
            }

            return std::wstring(domain.substr(secondLastDot + 1));
        }
        catch (...) {
            return std::wstring(domain);
        }
    }

    size_t NetworkBasedEvasionDetector::Impl::CountSubdomainLabels(std::wstring_view domain) const noexcept {
        if (domain.empty()) {
            return 0;
        }

        size_t count = 1;
        for (wchar_t c : domain) {
            if (c == L'.') {
                count++;
            }
        }

        return count;
    }

    std::wstring NetworkBasedEvasionDetector::Impl::GetLongestSubdomainLabel(std::wstring_view domain) const noexcept {
        try {
            std::wstring longest;
            size_t start = 0;

            for (size_t i = 0; i <= domain.length(); ++i) {
                if (i == domain.length() || domain[i] == L'.') {
                    size_t len = i - start;
                    if (len > longest.length()) {
                        longest = std::wstring(domain.substr(start, len));
                    }
                    start = i + 1;
                }
            }

            return longest;
        }
        catch (...) {
            return L"";
        }
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
            result.processName = Utils::ProcessUtils::GetProcessName(processId).value_or(L"");

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
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcess failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"AnalyzeProcess: Unknown error");

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
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcess (handle) failed: %hs", e.what());

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

            // ====================================================================
            // FP FIX #4: Connectivity Check Domains - INFORMATIONAL ONLY
            // Checking google.com/microsoft.com for connectivity is STANDARD
            // behavior for legitimate software including:
            // - Windows itself (msftconnecttest.com)
            // - Chrome, Edge, Firefox (captive portal detection)
            // - Office 365, Teams, OneDrive
            // - Virtually every modern application
            //
            // Original: 0.8 confidence (flagged as "likely malicious")
            // Fixed: 0.15 confidence (informational only, needs corroboration)
            // ====================================================================
            if (m_impl->IsConnectivityCheckDomain(domain)) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::CONN_DNSResolutionCheck);
                detection.confidence = 0.15; // Informational only - NOT suspicious alone
                detection.severity = NetworkEvasionSeverity::Low;
                detection.target = std::wstring(domain);
                detection.description = L"Connectivity check domain (normal behavior)";
                detection.technicalDetails = L"Standard internet connectivity verification";
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
                detection.confidence = std::min(0.9, entropy / 5.0);
                detection.target = std::wstring(domain);
                detection.description = L"High entropy domain name";
                detection.technicalDetails = std::format(L"Entropy: {:.2f}", entropy);
                outDetections.push_back(std::move(detection));
            }

            // Check DNS tunneling
            double tunnelConfidence = 0.0;
            std::wstring tunnelDetails;
            if (m_impl->DetectDNSTunneling(domain, tunnelConfidence, tunnelDetails)) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::DNS_Tunneling);
                detection.confidence = tunnelConfidence;
                detection.severity = NetworkEvasionSeverity::High;
                detection.target = std::wstring(domain);
                detection.description = L"DNS tunneling pattern detected";
                detection.technicalDetails = tunnelDetails;
                outDetections.push_back(std::move(detection));
            }

            // Check suspicious TLD
            if (m_impl->HasSuspiciousTLD(domain)) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_SuspiciousTLD);
                detection.confidence = 0.6;
                detection.target = std::wstring(domain);
                detection.description = L"Suspicious TLD: " + m_impl->GetTLD(domain);
                outDetections.push_back(std::move(detection));
            }

            // Check Dynamic DNS
            if (m_impl->IsDynamicDNSDomain(domain)) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_DynamicDNS);
                detection.confidence = 0.75;
                detection.severity = NetworkEvasionSeverity::High;
                detection.target = std::wstring(domain);
                detection.description = L"Dynamic DNS provider domain";
                outDetections.push_back(std::move(detection));
            }

            // Check cloud provider (potential abuse)
            if (m_impl->IsCloudProviderDomain(domain)) {
                NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_CloudProviderAbuse);
                detection.confidence = 0.5; // Lower confidence as cloud usage is common
                detection.target = std::wstring(domain);
                detection.description = L"Cloud provider domain (potential abuse)";
                outDetections.push_back(std::move(detection));
            }

            // Check against threat intel
            if (m_impl->m_threatIntel) {
                try {
                    std::string domainStr = Utils::StringUtils::ToNarrow(domain);
                    auto lookupResult = m_impl->m_threatIntel->LookupDomain(domainStr);

                    if (lookupResult.IsMalicious()) {
                        NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_KnownDomain);
                        detection.confidence = 0.99;
                        detection.severity = NetworkEvasionSeverity::Critical;
                        detection.target = std::wstring(domain);
                        detection.description = L"Malicious domain detected via Threat Intel";

                        if (lookupResult.category != ThreatIntel::ThreatCategory::Unknown) {
                            detection.technicalDetails = L"Category: " + Utils::StringUtils::ToWide(
                                ThreatIntel::ThreatCategoryToString(lookupResult.category)
                            );
                        }

                        outDetections.push_back(std::move(detection));
                        m_impl->m_stats.c2Detections++;
                    }
                    else if (lookupResult.IsSuspicious()) {
                        NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_LowReputation);
                        detection.confidence = 0.75;
                        detection.severity = NetworkEvasionSeverity::High;
                        detection.target = std::wstring(domain);
                        detection.description = L"Suspicious domain detected via Threat Intel";

                        if (lookupResult.category != ThreatIntel::ThreatCategory::Unknown) {
                            detection.technicalDetails = L"Category: " + Utils::StringUtils::ToWide(
                                ThreatIntel::ThreatCategoryToString(lookupResult.category)
                            );
                        }

                        outDetections.push_back(std::move(detection));
                    }
                }
                catch (...) {
                    // Swallow conversion errors
                }
            }

            // Check against custom C2 lists
            {
                std::shared_lock lock(m_impl->m_mutex);
                std::wstring domainLower(domain);
                std::transform(domainLower.begin(), domainLower.end(),
                    domainLower.begin(), ::towlower);

                if (m_impl->m_knownC2Domains.find(domainLower) != m_impl->m_knownC2Domains.end()) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_KnownDomain);
                    detection.confidence = 1.0;
                    detection.severity = NetworkEvasionSeverity::Critical;
                    detection.target = std::wstring(domain);
                    detection.description = L"Known C2 domain (custom list)";
                    outDetections.push_back(std::move(detection));

                    m_impl->m_stats.c2Detections++;
                }
            }

            return !outDetections.empty();
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeDomain failed: %hs", e.what());

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
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeDomains failed: %hs", e.what());

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
            SS_LOG_ERROR(LOG_CATEGORY, L"IsDGADomain failed: %hs", e.what());

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
            const std::array<std::wstring_view, 3> testDomains = {
                L"google.com", L"microsoft.com", L"cloudflare.com"
            };

            for (const auto& domain : testDomains) {
                std::vector<Utils::NetworkUtils::IpAddress> ipAddrs;
                if (Utils::NetworkUtils::ResolveHostname(domain, ipAddrs) && !ipAddrs.empty()) {
                    return true;
                }
            }

            return false;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckInternetConnectivity failed: %hs", e.what());

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
                L"HTTP_PROXY", L"HTTPS_PROXY", L"http_proxy", L"https_proxy",
                L"ALL_PROXY", L"all_proxy"
            };

            for (const auto& varName : proxyVars) {
                wchar_t buffer[1024] = {};
                const DWORD result = GetEnvironmentVariableW(varName.c_str(), buffer, _countof(buffer));

                if (result > 0 && result < _countof(buffer)) {
                    outProxyAddress = buffer;
                    return true;
                }
            }

            // Check Internet Explorer proxy settings using ANSI version
            INTERNET_PROXY_INFO proxyInfo = {};
            DWORD proxyInfoSize = sizeof(proxyInfo);

            if (InternetQueryOptionA(nullptr, INTERNET_OPTION_PROXY, &proxyInfo, &proxyInfoSize)) {
                // ================================================================
                // SECURITY FIX #5: RAII cleanup for proxy strings
                // Original code leaked memory if ToWide() threw an exception.
                // Use scope guards to ensure cleanup happens regardless of
                // exception paths.
                // ================================================================
                
                // RAII guards for automatic cleanup
                struct ProxyCleanup {
                    LPCSTR proxy = nullptr;
                    LPCSTR bypass = nullptr;
                    ~ProxyCleanup() {
                        if (proxy) GlobalFree((HGLOBAL)proxy);
                        if (bypass) GlobalFree((HGLOBAL)bypass);
                    }
                } cleanup;
                cleanup.proxy = proxyInfo.lpszProxy;
                cleanup.bypass = proxyInfo.lpszProxyBypass;

                if (proxyInfo.lpszProxy && proxyInfo.lpszProxy[0] != '\0') {
                    outProxyAddress = Utils::StringUtils::ToWide(proxyInfo.lpszProxy);
                    return true;
                }
                // cleanup destructor runs here, freeing both strings
            }

            return false;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectProxy failed: %hs", e.what());

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
            bool vpnDetected = false;
            bool vmMacDetected = false;
            std::wstring vmMacInfo;
            std::vector<std::wstring> adapterDetails;

            if (m_impl->CheckNetworkAdapters(vpnDetected, outVPNAdapter, vmMacDetected, vmMacInfo, adapterDetails, err)) {
                return vpnDetected;
            }

            return false;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectVPN failed: %hs", e.what());

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
            // 1. Check for Tor listening ports via TCP Table
            DWORD tableSize = 0;
            DWORD result = GetExtendedTcpTable(nullptr, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);

            if (result != ERROR_INSUFFICIENT_BUFFER) {
                if (result == NO_ERROR) {
                    return false; // Empty table
                }
                if (err) {
                    err->win32Code = result;
                    err->message = L"GetExtendedTcpTable size query failed";
                }
                return false;
            }

            std::vector<uint8_t> buffer(tableSize);
            PMIB_TCPTABLE_OWNER_PID table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

            result = GetExtendedTcpTable(table, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
            if (result != NO_ERROR) {
                if (err) {
                    err->win32Code = result;
                    err->message = L"GetExtendedTcpTable failed";
                }
                return false;
            }

            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                const uint16_t port = ntohs(static_cast<uint16_t>(table->table[i].dwLocalPort));

                if (port == TOR_SOCKS_PORT || port == TOR_BROWSER_PORT || port == TOR_CONTROL_PORT) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Tor listener detected on port %u (PID: %u)",
                        port, table->table[i].dwOwningPid);
                    return true;
                }
            }

            // 2. Check for Tor-related processes
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32 = {};
                pe32.dwSize = sizeof(pe32);

                if (Process32FirstW(hSnapshot, &pe32)) {
                    do {
                        std::wstring processName = pe32.szExeFile;
                        std::wstring lowerName = processName;
                        std::transform(lowerName.begin(), lowerName.end(),
                            lowerName.begin(), ::towlower);

                        // ================================================================
                        // FP FIX #2: Removed firefox.exe from Tor detection
                        // The original code flagged ALL Firefox instances as Tor-related.
                        // Firefox is used by 200M+ users - this caused massive FPs.
                        // Tor Browser does use Firefox, but we detect it via:
                        //   1. tor.exe process (always runs with Tor Browser)
                        //   2. Tor ports (9050, 9150, 9051) - checked separately
                        //   3. tor-browser.exe (the launcher)
                        // Regular Firefox without tor.exe running is LEGITIMATE.
                        // ================================================================
                        if (lowerName == L"tor.exe" ||
                            lowerName == L"tor-browser.exe" ||
                            lowerName == L"vidalia.exe" ||
                            lowerName == L"obfs4proxy.exe" ||    // Tor bridge proxy
                            lowerName == L"snowflake-client.exe") { // Tor censorship circumvention

                            CloseHandle(hSnapshot);
                            SS_LOG_WARN(LOG_CATEGORY, L"Tor-related process detected: %ls", processName.c_str());
                            return true;
                        }
                    } while (Process32NextW(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }

            return false;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectTor failed: %hs", e.what());

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
                return false;
            }

            outInfo.timestamps = timestamps;
            outInfo.beaconCount = timestamps.size();

            // Calculate regularity with jitter tolerance
            outInfo.regularityScore = m_impl->CalculateBeaconingRegularity(timestamps);

            // Calculate average interval
            std::vector<double> intervals;
            for (size_t i = 1; i < timestamps.size(); ++i) {
                const auto duration = timestamps[i] - timestamps[i - 1];
                double seconds = std::chrono::duration<double>(duration).count();
                if (seconds > 0.0) {
                    intervals.push_back(seconds);
                }
            }

            if (intervals.empty()) {
                return false;
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

            // Additional check: detect multi-interval beaconing
            if (!outInfo.isBeaconing && timestamps.size() >= 10) {
                std::vector<double> detectedIntervals;
                if (m_impl->DetectMultiIntervalBeaconing(timestamps, detectedIntervals)) {
                    outInfo.isBeaconing = true;
                    outInfo.regularityScore = 0.85; // High confidence for multi-interval
                }
            }

            if (outInfo.isBeaconing) {
                m_impl->m_stats.beaconingDetections++;
            }

            return outInfo.isBeaconing;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectBeaconing failed: %hs", e.what());

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
                std::vector<Utils::NetworkUtils::IpAddress> ipAddrs;
                if (Utils::NetworkUtils::ResolveHostname(domain, ipAddrs)) {
                    for (const auto& ip : ipAddrs) {
                        std::wstring ipStr = ip.ToString();
                        if (uniqueIPs.insert(ipStr).second) {
                            outInfo.observedIPs.push_back(ipStr);
                            outInfo.changeTimestamps.push_back(std::chrono::system_clock::now());
                        }
                    }
                }

                // Small delay between queries
                if (i < numQueries - 1) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }

            outInfo.ipChangeCount = outInfo.observedIPs.size();

            // Fast flux: many different IPs for same domain
            outInfo.isFastFlux = (outInfo.ipChangeCount >= NetworkEvasionConstants::MIN_FAST_FLUX_IP_CHANGES);

            return outInfo.isFastFlux;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectFastFlux failed: %hs", e.what());

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

            SS_LOG_INFO(LOG_CATEGORY, L"Started monitoring process %u", processId);
            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"StartMonitoring failed: %hs", e.what());

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

            SS_LOG_INFO(LOG_CATEGORY, L"Stopped monitoring process %u", processId);
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"StopMonitoring: Exception");
        }
    }

    void NetworkBasedEvasionDetector::StopAllMonitoring() noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_monitoringProcesses.clear();
            m_impl->m_monitoringActive = false;

            SS_LOG_INFO(LOG_CATEGORY, L"Stopped all monitoring");
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"StopAllMonitoring: Exception");
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
        std::wstring lowerDomain(domain);
        std::transform(lowerDomain.begin(), lowerDomain.end(),
            lowerDomain.begin(), ::towlower);
        m_impl->m_knownC2Domains.insert(lowerDomain);
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
        try {
            // Analyze network configuration
            if (HasFlag(config.flags, NetworkAnalysisFlags::ScanNetworkConfig)) {
                CheckNetworkConfiguration(result);
            }

            // Analyze connectivity checks
            if (HasFlag(config.flags, NetworkAnalysisFlags::ScanConnectivity)) {
                CheckConnectivity(result);
            }

            // ====================================================================
            // SECURITY FIX #1: TOCTOU Race Condition Prevention
            // Copy tracking data while holding the lock to avoid data races.
            // The original code released the lock before passing references to
            // Check* functions, allowing concurrent modification during analysis.
            // ====================================================================

            // Analyze DNS activity
            if (HasFlag(config.flags, NetworkAnalysisFlags::ScanDNS)) {
                // Copy data while holding lock to prevent TOCTOU
                std::vector<std::chrono::system_clock::time_point> dnsTimestamps;
                std::unordered_map<std::wstring, std::vector<std::wstring>> dnsDomainToIPs;
                {
                    std::shared_lock lock(m_impl->m_mutex);
                    auto it = m_impl->m_dnsTracking.find(processId);
                    if (it != m_impl->m_dnsTracking.end()) {
                        dnsTimestamps = it->second.timestamps;
                        dnsDomainToIPs = it->second.domainToIPs;
                    }
                }
                // Now analyze with our local copy (lock released)
                if (!dnsTimestamps.empty() || !dnsDomainToIPs.empty()) {
                    CheckDNSEvasion(dnsTimestamps, dnsDomainToIPs, result);
                }
            }

            // Analyze traffic patterns
            if (HasFlag(config.flags, NetworkAnalysisFlags::ScanTrafficPatterns)) {
                // Copy data while holding lock to prevent TOCTOU
                std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>> targetTimestamps;
                {
                    std::shared_lock lock(m_impl->m_mutex);
                    auto it = m_impl->m_connectionTracking.find(processId);
                    if (it != m_impl->m_connectionTracking.end()) {
                        targetTimestamps = it->second.targetTimestamps;
                    }
                }
                if (!targetTimestamps.empty()) {
                    CheckTrafficPatterns(targetTimestamps, result);
                }
            }

            // Analyze beaconing
            if (HasFlag(config.flags, NetworkAnalysisFlags::ScanBeaconing)) {
                // Copy data while holding lock to prevent TOCTOU
                std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>> targetTimestamps;
                {
                    std::shared_lock lock(m_impl->m_mutex);
                    auto it = m_impl->m_connectionTracking.find(processId);
                    if (it != m_impl->m_connectionTracking.end()) {
                        targetTimestamps = it->second.targetTimestamps;
                    }
                }
                if (!targetTimestamps.empty()) {
                    CheckBeaconing(targetTimestamps, result);
                }
            }

            // Check for network capture tools (anti-analysis)
            if (HasFlag(config.flags, NetworkAnalysisFlags::ScanAntiAnalysis)) {
                std::vector<std::wstring> captureTools;
                if (m_impl->DetectNetworkCaptureTools(captureTools)) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::ANTI_NetworkCaptureDetection);
                    detection.confidence = 0.9;
                    detection.severity = NetworkEvasionSeverity::High;
                    detection.description = L"Network capture tools detected";

                    std::wstring toolList;
                    for (const auto& tool : captureTools) {
                        if (!toolList.empty()) toolList += L", ";
                        toolList += tool;
                    }
                    detection.technicalDetails = L"Tools: " + toolList;

                    AddDetection(result, std::move(detection));
                }

                // Check for sandbox network
                std::wstring sandboxDetails;
                if (m_impl->DetectSandboxNetwork(sandboxDetails)) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::ANTI_SandboxNetwork);
                    detection.confidence = 0.85;
                    detection.severity = NetworkEvasionSeverity::High;
                    detection.description = L"Sandbox network characteristics detected";
                    detection.technicalDetails = sandboxDetails;
                    AddDetection(result, std::move(detection));
                }
            }

            // Calculate evasion score
            CalculateEvasionScore(result);
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcessInternal: Exception");
        }
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
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckConnectivity: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckDNSEvasion(
        const std::vector<std::chrono::system_clock::time_point>& timestamps,
        const std::unordered_map<std::wstring, std::vector<std::wstring>>& domainToIPs,
        NetworkEvasionResult& result
    ) noexcept {
        try {
            result.totalDNSQueries = static_cast<uint32_t>(timestamps.size());
            m_impl->m_stats.totalDNSQueries += result.totalDNSQueries;

            // Check for excessive DNS queries
            if (!timestamps.empty()) {
                const auto now = std::chrono::system_clock::now();
                const auto oneMinuteAgo = now - std::chrono::minutes(1);

                size_t recentQueries = 0;
                for (const auto& ts : timestamps) {
                    if (ts >= oneMinuteAgo) {
                        recentQueries++;
                    }
                }

                // ================================================================
                // FP FIX #6: DNS Query Threshold - Increased and Scaled Confidence
                // Original: 50 queries/min at 0.8 confidence - WAY too aggressive
                // Modern web apps, browsers with many tabs, SPAs with CDNs can
                // easily exceed 50 queries/minute during normal operation.
                //
                // NEW: Threshold raised to 200/min (constant updated in hpp)
                // Confidence scaled by how much the threshold is exceeded.
                // ================================================================
                if (recentQueries > NetworkEvasionConstants::MAX_NORMAL_DNS_QUERIES) {
                    // Scale confidence based on severity
                    // 200-300: 0.25, 300-500: 0.40, 500-1000: 0.55, 1000+: 0.70
                    double confidence = 0.25;
                    if (recentQueries > 1000) {
                        confidence = 0.70;
                    } else if (recentQueries > 500) {
                        confidence = 0.55;
                    } else if (recentQueries > 300) {
                        confidence = 0.40;
                    }

                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::DNS_ExcessiveLookups);
                    detection.confidence = confidence;
                    detection.severity = (recentQueries > 500) ? NetworkEvasionSeverity::Medium : NetworkEvasionSeverity::Low;
                    detection.description = L"Elevated DNS query rate";
                    detection.technicalDetails = std::format(L"Queries per minute: {} (threshold: {})", 
                                                             recentQueries, NetworkEvasionConstants::MAX_NORMAL_DNS_QUERIES);
                    AddDetection(result, std::move(detection));
                }
            }

            // Check each domain for DGA, fast flux, tunneling, etc.
            for (const auto& [domain, ips] : domainToIPs) {
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
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckDNSEvasion: Exception");
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

            // Check for VPN and VM MAC addresses
            bool vpnDetected = false;
            std::wstring vpnName;
            bool vmMacDetected = false;
            std::wstring vmMacInfo;
            std::vector<std::wstring> adapterDetails;

            if (m_impl->CheckNetworkAdapters(vpnDetected, vpnName, vmMacDetected, vmMacInfo, adapterDetails, nullptr)) {
                if (vpnDetected) {
                    result.networkConfig.hasVPN = true;
                    result.networkConfig.vpnAdapter = vpnName;

                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::NET_VPNDetection);
                    detection.confidence = 0.7;
                    detection.description = L"VPN detected";
                    detection.detectedValue = vpnName;
                    AddDetection(result, std::move(detection));
                }

                if (vmMacDetected) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::NET_MACRandomization);
                    detection.confidence = 0.95;
                    detection.description = L"Virtual Machine MAC Address OUI detected";
                    detection.detectedValue = vmMacInfo;
                    detection.severity = NetworkEvasionSeverity::High;
                    AddDetection(result, std::move(detection));
                }

                // Store adapter info
                result.networkConfig.adapters = adapterDetails;
            }

            // Check for Tor
            if (DetectTor(nullptr)) {
                result.networkConfig.hasTor = true;

                NetworkDetectedTechnique detection(NetworkEvasionTechnique::NET_TorDetection);
                detection.confidence = 0.85;
                detection.severity = NetworkEvasionSeverity::High;
                detection.description = L"Tor detected";
                AddDetection(result, std::move(detection));
            }

            result.networkConfig.valid = true;
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckNetworkConfiguration: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckTrafficPatterns(
        const std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>>& targetTimestamps,
        NetworkEvasionResult& result
    ) noexcept {
        try {
            result.totalConnections = 0;

            for (const auto& [target, timestamps] : targetTimestamps) {
                result.totalConnections += static_cast<uint32_t>(timestamps.size());
            }

            m_impl->m_stats.totalHTTPRequests += result.totalConnections;

            // Check for connection rate anomalies
            if (!targetTimestamps.empty()) {
                auto now = std::chrono::system_clock::now();
                auto oneMinuteAgo = now - std::chrono::minutes(1);

                size_t recentConnections = 0;
                for (const auto& [target, timestamps] : targetTimestamps) {
                    for (const auto& ts : timestamps) {
                        if (ts >= oneMinuteAgo) {
                            recentConnections++;
                        }
                    }
                }

                if (recentConnections > NetworkEvasionConstants::MAX_NORMAL_CONNECTION_RATE) {
                    NetworkDetectedTechnique detection(NetworkEvasionTechnique::TRAFFIC_RateLimiting);
                    detection.confidence = 0.7;
                    detection.description = L"High connection rate detected";
                    detection.technicalDetails = std::format(L"Connections per minute: {}", recentConnections);
                    AddDetection(result, std::move(detection));
                }
            }
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckTrafficPatterns: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckBeaconing(
        const std::map<std::wstring, std::vector<std::chrono::system_clock::time_point>>& targetTimestamps,
        NetworkEvasionResult& result
    ) noexcept {
        try {
            for (const auto& [target, timestamps] : targetTimestamps) {
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
                            L"Regularity: {:.2f}, Avg interval: {:.2f}s, Beacons: {}",
                            beaconInfo.regularityScore,
                            beaconInfo.averageIntervalSec,
                            beaconInfo.beaconCount
                        );
                        AddDetection(result, std::move(detection));
                    }
                }
            }
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckBeaconing: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CheckC2Infrastructure(
        const std::vector<std::wstring>& domains,
        const std::vector<std::wstring>& ips,
        NetworkEvasionResult& result
    ) noexcept {
        try {
            // Check domains against known C2 lists
            for (const auto& domain : domains) {
                std::vector<NetworkDetectedTechnique> detections;
                AnalyzeDomain(domain, detections, nullptr);

                for (auto& detection : detections) {
                    AddDetection(result, std::move(detection));
                }
            }

            // Check IPs against known C2 lists
            {
                std::shared_lock lock(m_impl->m_mutex);
                for (const auto& ip : ips) {
                    if (m_impl->m_knownC2IPs.find(ip) != m_impl->m_knownC2IPs.end()) {
                        NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_KnownIP);
                        detection.confidence = 1.0;
                        detection.severity = NetworkEvasionSeverity::Critical;
                        detection.target = ip;
                        detection.description = L"Known C2 IP address";
                        AddDetection(result, std::move(detection));

                        m_impl->m_stats.c2Detections++;
                    }
                }
            }

            // Check IPs against threat intel
            if (m_impl->m_threatIntel) {
                for (const auto& ip : ips) {
                    try {
                        std::string ipStr = Utils::StringUtils::ToNarrow(ip);
                        auto lookupResult = m_impl->m_threatIntel->LookupIPv4(ipStr);

                        if (lookupResult.IsMalicious()) {
                            NetworkDetectedTechnique detection(NetworkEvasionTechnique::C2_KnownIP);
                            detection.confidence = 0.95;
                            detection.severity = NetworkEvasionSeverity::Critical;
                            detection.target = ip;
                            detection.description = L"Malicious IP detected via Threat Intel";
                            AddDetection(result, std::move(detection));

                            m_impl->m_stats.c2Detections++;
                        }
                    }
                    catch (...) {
                        // Swallow conversion errors
                    }
                }
            }
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckC2Infrastructure: Exception");
        }
    }

    void NetworkBasedEvasionDetector::CalculateEvasionScore(NetworkEvasionResult& result) noexcept {
        try {
            double score = 0.0;
            NetworkEvasionSeverity maxSev = NetworkEvasionSeverity::Low;

            for (const auto& detection : result.detectedTechniques) {
                // Weight by category
                double categoryWeight = detection.weight;
                if (categoryWeight <= 0.0) {
                    categoryWeight = 1.0;
                }

                // Weight by severity
                double severityMultiplier = 1.0;
                switch (detection.severity) {
                case NetworkEvasionSeverity::Low:      severityMultiplier = 1.0; break;
                case NetworkEvasionSeverity::Medium:   severityMultiplier = 2.5; break;
                case NetworkEvasionSeverity::High:     severityMultiplier = 5.0; break;
                case NetworkEvasionSeverity::Critical: severityMultiplier = 10.0; break;
                }

                score += (categoryWeight * severityMultiplier * detection.confidence);

                if (detection.severity > maxSev) {
                    maxSev = detection.severity;
                }
            }

            result.evasionScore = std::min(score, 100.0);
            result.maxSeverity = maxSev;
            result.isEvasive = (score >= 50.0) ||
                (maxSev >= NetworkEvasionSeverity::High);
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CalculateEvasionScore: Exception");
        }
    }

    void NetworkBasedEvasionDetector::AddDetection(
        NetworkEvasionResult& result,
        NetworkDetectedTechnique detection
    ) noexcept {
        try {
            // Set category bit
            const auto catIdx = static_cast<uint32_t>(detection.category);
            if (catIdx < 32) {
                result.detectedCategories |= (1u << catIdx);
                m_impl->m_stats.categoryDetections[catIdx % 16]++;
            }

            result.totalDetections++;
            m_impl->m_stats.totalDetections++;

            // Track suspicious domains/IPs
            if (!detection.target.empty()) {
                if (m_impl->IsValidIPv4(detection.target)) {
                    result.suspiciousIPs.push_back(detection.target);
                }
                else if (m_impl->IsValidDomain(detection.target)) {
                    result.suspiciousDomains.push_back(detection.target);
                }

                // Track known C2
                if (detection.technique == NetworkEvasionTechnique::C2_KnownDomain ||
                    detection.technique == NetworkEvasionTechnique::C2_KnownIP) {
                    result.knownC2.push_back(detection.target);
                }
            }

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
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AddDetection: Exception");
        }
    }

    double NetworkBasedEvasionDetector::CalculateDomainEntropy(std::wstring_view domain) const noexcept {
        return m_impl->CalculateDomainEntropy(domain);
    }

    double NetworkBasedEvasionDetector::CalculateDGAScore(std::wstring_view domain) const noexcept {
        return m_impl->CalculateDGAScore(domain);
    }

} // namespace ShadowStrike::AntiEvasion
