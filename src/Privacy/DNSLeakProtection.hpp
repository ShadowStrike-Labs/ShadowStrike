/**
 * ============================================================================
 * ShadowStrike NGAV - DNS LEAK PROTECTION MODULE
 * ============================================================================
 *
 * @file DNSLeakProtection.hpp
 * @brief Enterprise-grade DNS leak protection with DoH/DoT support,
 *        DNS hijack detection, and cache poisoning prevention.
 *
 * Provides comprehensive DNS privacy protection including encrypted DNS
 * enforcement, leak detection, and resolver integrity verification.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. ENCRYPTED DNS
 *    - DNS-over-HTTPS (DoH)
 *    - DNS-over-TLS (DoT)
 *    - DNS-over-QUIC (DoQ)
 *    - DNSSEC validation
 *    - Multiple provider support
 *
 * 2. LEAK DETECTION
 *    - VPN bypass detection
 *    - IPv6 DNS leaks
 *    - WebRTC DNS leaks
 *    - Split tunnel leaks
 *    - Fallback DNS detection
 *
 * 3. HIJACK DETECTION
 *    - Resolver modification alerts
 *    - Network adapter monitoring
 *    - DHCP DNS override detection
 *    - Malware DNS redirection
 *    - Router DNS hijacking
 *
 * 4. CACHE POISONING PROTECTION
 *    - DNSSEC validation
 *    - Cross-reference verification
 *    - TTL monitoring
 *    - Response validation
 *    - NXDOMAIN protection
 *
 * 5. DNS FILTERING
 *    - Malware domain blocking
 *    - Tracker domain blocking
 *    - Parental controls
 *    - Custom blocklists
 *    - Whitelist exceptions
 *
 * SUPPORTED PROVIDERS:
 * ====================
 * - Cloudflare (1.1.1.1)
 * - Google Public DNS
 * - Quad9
 * - NextDNS
 * - AdGuard DNS
 * - Custom providers
 *
 * @note Requires network driver for full leak prevention.
 * @note Thread-safe singleton design.
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
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>

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
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../PatternStore/PatternStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class DNSLeakProtectionImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DNSConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Standard DNS port
    inline constexpr uint16_t DNS_PORT = 53;
    
    /// @brief DoH port
    inline constexpr uint16_t DOH_PORT = 443;
    
    /// @brief DoT port
    inline constexpr uint16_t DOT_PORT = 853;
    
    /// @brief Maximum DNS cache entries
    inline constexpr size_t MAX_DNS_CACHE = 10000;
    
    /// @brief Default query timeout (ms)
    inline constexpr uint32_t DEFAULT_TIMEOUT_MS = 5000;

    /// @brief Known DoH providers
    struct DoHProvider {
        const char* name;
        const char* url;
        const char* ip;
    };

    inline constexpr DoHProvider DOH_PROVIDERS[] = {
        {"Cloudflare", "https://cloudflare-dns.com/dns-query", "1.1.1.1"},
        {"Cloudflare Family", "https://family.cloudflare-dns.com/dns-query", "1.1.1.3"},
        {"Google", "https://dns.google/dns-query", "8.8.8.8"},
        {"Quad9", "https://dns.quad9.net/dns-query", "9.9.9.9"},
        {"Quad9 Secured", "https://dns11.quad9.net/dns-query", "9.9.9.11"},
        {"NextDNS", "https://dns.nextdns.io/", "45.90.28.0"},
        {"AdGuard", "https://dns.adguard-dns.com/dns-query", "94.140.14.14"}
    };

}  // namespace DNSConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief DNS protocol
 */
enum class DNSProtocol : uint8_t {
    Standard        = 0,    ///< Traditional UDP/53
    DoH             = 1,    ///< DNS-over-HTTPS
    DoT             = 2,    ///< DNS-over-TLS
    DoQ             = 3,    ///< DNS-over-QUIC
    DNSSEC          = 4     ///< With DNSSEC validation
};

/**
 * @brief Leak type
 */
enum class DNSLeakType : uint8_t {
    None            = 0,
    VPNBypass       = 1,    ///< DNS not going through VPN
    IPv6Leak        = 2,    ///< IPv6 DNS leak
    WebRTCLeak      = 3,    ///< WebRTC DNS leak
    SplitTunnel     = 4,    ///< Split tunneling leak
    FallbackLeak    = 5,    ///< Fallback to insecure DNS
    DHCPOverride    = 6,    ///< DHCP changed DNS
    MalwareRedirect = 7     ///< Malware DNS hijack
};

/**
 * @brief DNS record type
 */
enum class DNSRecordType : uint8_t {
    A               = 1,    ///< IPv4 address
    AAAA            = 28,   ///< IPv6 address
    CNAME           = 5,    ///< Canonical name
    MX              = 15,   ///< Mail exchange
    TXT             = 16,   ///< Text record
    NS              = 2,    ///< Name server
    SOA             = 6,    ///< Start of authority
    PTR             = 12,   ///< Pointer
    SRV             = 33,   ///< Service
    CAA             = 257,  ///< Certification Authority Authorization
    DNSKEY          = 48,   ///< DNSSEC key
    DS              = 43,   ///< Delegation signer
    RRSIG           = 46    ///< DNSSEC signature
};

/**
 * @brief Response status
 */
enum class DNSResponseStatus : uint8_t {
    Success         = 0,    ///< NOERROR
    FormatError     = 1,    ///< FORMERR
    ServerFailure   = 2,    ///< SERVFAIL
    NonExistent     = 3,    ///< NXDOMAIN
    NotImplemented  = 4,    ///< NOTIMP
    Refused         = 5,    ///< REFUSED
    Timeout         = 100,  ///< Custom: timeout
    NetworkError    = 101,  ///< Custom: network error
    Blocked         = 102   ///< Custom: blocked by filter
};

/**
 * @brief Cache poisoning status
 */
enum class PoisoningStatus : uint8_t {
    Clean           = 0,
    Suspicious      = 1,
    Poisoned        = 2,
    Verified        = 3
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Monitoring      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief DNS query
 */
struct DNSQuery {
    /// @brief Query ID
    uint64_t queryId = 0;
    
    /// @brief Domain name
    std::string domain;
    
    /// @brief Record type
    DNSRecordType recordType = DNSRecordType::A;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::string processName;
    
    /// @brief Target DNS server
    std::string dnsServer;
    
    /// @brief Target port
    uint16_t port = DNSConstants::DNS_PORT;
    
    /// @brief Protocol
    DNSProtocol protocol = DNSProtocol::Standard;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DNS response
 */
struct DNSResponse {
    /// @brief Query this responds to
    uint64_t queryId = 0;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Status
    DNSResponseStatus status = DNSResponseStatus::Success;
    
    /// @brief Resolved addresses
    std::vector<std::string> addresses;
    
    /// @brief CNAME chain
    std::vector<std::string> cnameChain;
    
    /// @brief TTL (seconds)
    uint32_t ttl = 0;
    
    /// @brief Response time (ms)
    uint32_t responseTimeMs = 0;
    
    /// @brief Server that responded
    std::string server;
    
    /// @brief DNSSEC validated
    bool dnssecValidated = false;
    
    /// @brief Poisoning status
    PoisoningStatus poisoningStatus = PoisoningStatus::Clean;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DNS leak event
 */
struct DNSLeakEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Leak type
    DNSLeakType leakType = DNSLeakType::None;
    
    /// @brief Query that leaked
    DNSQuery query;
    
    /// @brief Expected DNS server (VPN)
    std::string expectedServer;
    
    /// @brief Actual DNS server used
    std::string actualServer;
    
    /// @brief VPN active
    bool vpnActive = false;
    
    /// @brief Description
    std::string description;
    
    /// @brief Severity (1-10)
    int severity = 5;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DNS hijack alert
 */
struct DNSHijackAlert {
    /// @brief Alert ID
    uint64_t alertId = 0;
    
    /// @brief Type
    std::string alertType;
    
    /// @brief Previous DNS servers
    std::vector<std::string> previousServers;
    
    /// @brief New DNS servers
    std::vector<std::string> newServers;
    
    /// @brief Source of change
    std::string changeSource;  // "DHCP", "Malware", "User", etc.
    
    /// @brief Process ID (if malware)
    uint32_t suspectPid = 0;
    
    /// @brief Process name (if malware)
    std::string suspectProcess;
    
    /// @brief Severity
    int severity = 5;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Auto-remediated
    bool remediated = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DNS provider
 */
struct DNSProvider {
    /// @brief Provider ID
    std::string providerId;
    
    /// @brief Provider name
    std::string name;
    
    /// @brief Primary URL (for DoH)
    std::string primaryUrl;
    
    /// @brief Backup URL
    std::string backupUrl;
    
    /// @brief Primary IP
    std::string primaryIp;
    
    /// @brief Backup IP
    std::string backupIp;
    
    /// @brief Protocol
    DNSProtocol protocol = DNSProtocol::DoH;
    
    /// @brief Port
    uint16_t port = DNSConstants::DOH_PORT;
    
    /// @brief Supports DNSSEC
    bool supportsDNSSEC = true;
    
    /// @brief Is malware filtering enabled
    bool malwareFiltering = false;
    
    /// @brief Is adult content filtering enabled
    bool adultFiltering = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DNS cache entry
 */
struct DNSCacheEntry {
    /// @brief Domain
    std::string domain;
    
    /// @brief Record type
    DNSRecordType recordType = DNSRecordType::A;
    
    /// @brief Resolved addresses
    std::vector<std::string> addresses;
    
    /// @brief TTL remaining
    uint32_t ttlRemaining = 0;
    
    /// @brief Original TTL
    uint32_t originalTtl = 0;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Expiration time
    SystemTimePoint expirationTime;
    
    /// @brief Source provider
    std::string source;
    
    /// @brief Hit count
    uint32_t hitCount = 0;
    
    [[nodiscard]] bool IsExpired() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct DNSStatistics {
    std::atomic<uint64_t> totalQueries{0};
    std::atomic<uint64_t> encryptedQueries{0};
    std::atomic<uint64_t> leaksDetected{0};
    std::atomic<uint64_t> leaksBlocked{0};
    std::atomic<uint64_t> hijackAttemptsDetected{0};
    std::atomic<uint64_t> poisoningAttemptsDetected{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> blockedDomains{0};
    std::atomic<uint64_t> dnssecValidations{0};
    std::atomic<uint64_t> dnssecFailures{0};
    std::atomic<uint64_t> averageResponseTimeMs{0};
    std::array<std::atomic<uint64_t>, 8> byProtocol{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct DNSConfiguration {
    /// @brief Enable DNS protection
    bool enabled = true;
    
    /// @brief Force encrypted DNS
    bool forceEncryptedDNS = true;
    
    /// @brief Preferred protocol
    DNSProtocol preferredProtocol = DNSProtocol::DoH;
    
    /// @brief Primary provider
    DNSProvider primaryProvider;
    
    /// @brief Backup provider
    DNSProvider backupProvider;
    
    /// @brief Enable leak detection
    bool enableLeakDetection = true;
    
    /// @brief Block on leak detected
    bool blockOnLeak = true;
    
    /// @brief Enable hijack detection
    bool enableHijackDetection = true;
    
    /// @brief Auto-remediate hijacks
    bool autoRemediateHijacks = true;
    
    /// @brief Enable cache poisoning detection
    bool enablePoisoningDetection = true;
    
    /// @brief Enable DNSSEC validation
    bool enableDNSSEC = true;
    
    /// @brief Enable local caching
    bool enableCache = true;
    
    /// @brief Cache TTL override (0 = use server TTL)
    uint32_t cacheTtlOverride = 0;
    
    /// @brief Block IPv6 DNS (leak prevention)
    bool blockIPv6DNS = false;
    
    /// @brief Query timeout (ms)
    uint32_t queryTimeoutMs = DNSConstants::DEFAULT_TIMEOUT_MS;
    
    /// @brief Blocked domains
    std::vector<std::string> blockedDomains;
    
    /// @brief Whitelisted domains
    std::vector<std::string> whitelistedDomains;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using QueryCallback = std::function<void(const DNSQuery&)>;
using ResponseCallback = std::function<void(const DNSResponse&)>;
using LeakCallback = std::function<void(const DNSLeakEvent&)>;
using HijackCallback = std::function<void(const DNSHijackAlert&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// DNS LEAK PROTECTION CLASS
// ============================================================================

/**
 * @class DNSLeakProtection
 * @brief Enterprise DNS privacy protection
 */
class DNSLeakProtection final {
public:
    [[nodiscard]] static DNSLeakProtection& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    DNSLeakProtection(const DNSLeakProtection&) = delete;
    DNSLeakProtection& operator=(const DNSLeakProtection&) = delete;
    DNSLeakProtection(DNSLeakProtection&&) = delete;
    DNSLeakProtection& operator=(DNSLeakProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const DNSConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const DNSConfiguration& config);
    [[nodiscard]] DNSConfiguration GetConfiguration() const;

    // ========================================================================
    // SECURE DNS
    // ========================================================================
    
    /// @brief Enable secure DNS
    [[nodiscard]] bool EnableSecureDns(const std::string& providerUrl);
    
    /// @brief Disable secure DNS
    [[nodiscard]] bool DisableSecureDns();
    
    /// @brief Is secure DNS enabled
    [[nodiscard]] bool IsSecureDnsEnabled() const noexcept;
    
    /// @brief Set DNS provider
    [[nodiscard]] bool SetProvider(const DNSProvider& provider);
    
    /// @brief Get current provider
    [[nodiscard]] DNSProvider GetCurrentProvider() const;
    
    /// @brief Get available providers
    [[nodiscard]] std::vector<DNSProvider> GetAvailableProviders() const;

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Start DNS monitoring
    [[nodiscard]] bool MonitorDnsActivity();
    
    /// @brief Stop DNS monitoring
    void StopMonitoring();
    
    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoringActive() const noexcept;

    // ========================================================================
    // LEAK DETECTION
    // ========================================================================
    
    /// @brief Check for DNS leaks
    [[nodiscard]] std::vector<DNSLeakEvent> CheckForLeaks();
    
    /// @brief Is VPN DNS leak detected
    [[nodiscard]] bool IsVPNLeakDetected() const noexcept;
    
    /// @brief Get recent leaks
    [[nodiscard]] std::vector<DNSLeakEvent> GetRecentLeaks(size_t limit = 100);

    // ========================================================================
    // HIJACK DETECTION
    // ========================================================================
    
    /// @brief Check for DNS hijacking
    [[nodiscard]] std::vector<DNSHijackAlert> CheckForHijacking();
    
    /// @brief Get current system DNS servers
    [[nodiscard]] std::vector<std::string> GetSystemDNSServers();
    
    /// @brief Restore DNS settings
    [[nodiscard]] bool RestoreDNSSettings();
    
    /// @brief Get recent hijack alerts
    [[nodiscard]] std::vector<DNSHijackAlert> GetRecentHijackAlerts(size_t limit = 100);

    // ========================================================================
    // CACHE POISONING
    // ========================================================================
    
    /// @brief Check DNS cache for poisoning
    [[nodiscard]] std::vector<DNSCacheEntry> CheckCacheForPoisoning();
    
    /// @brief Verify domain resolution
    [[nodiscard]] PoisoningStatus VerifyDomainResolution(const std::string& domain);
    
    /// @brief Clear DNS cache
    [[nodiscard]] bool ClearDNSCache();

    // ========================================================================
    // DNS QUERIES
    // ========================================================================
    
    /// @brief Resolve domain using secure DNS
    [[nodiscard]] DNSResponse ResolveDomain(
        const std::string& domain,
        DNSRecordType recordType = DNSRecordType::A);
    
    /// @brief Get cached entry
    [[nodiscard]] std::optional<DNSCacheEntry> GetCachedEntry(
        const std::string& domain);
    
    /// @brief Get all cache entries
    [[nodiscard]] std::vector<DNSCacheEntry> GetCacheEntries();

    // ========================================================================
    // FILTERING
    // ========================================================================
    
    /// @brief Block domain
    [[nodiscard]] bool BlockDomain(const std::string& domain);
    
    /// @brief Unblock domain
    [[nodiscard]] bool UnblockDomain(const std::string& domain);
    
    /// @brief Is domain blocked
    [[nodiscard]] bool IsDomainBlocked(const std::string& domain);
    
    /// @brief Whitelist domain
    [[nodiscard]] bool WhitelistDomain(const std::string& domain);
    
    /// @brief Import blocklist
    [[nodiscard]] bool ImportBlocklist(const fs::path& listPath);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterQueryCallback(QueryCallback callback);
    void RegisterResponseCallback(ResponseCallback callback);
    void RegisterLeakCallback(LeakCallback callback);
    void RegisterHijackCallback(HijackCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] DNSStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    DNSLeakProtection();
    ~DNSLeakProtection();
    
    std::unique_ptr<DNSLeakProtectionImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDNSProtocolName(DNSProtocol protocol) noexcept;
[[nodiscard]] std::string_view GetLeakTypeName(DNSLeakType type) noexcept;
[[nodiscard]] std::string_view GetRecordTypeName(DNSRecordType type) noexcept;
[[nodiscard]] std::string_view GetResponseStatusName(DNSResponseStatus status) noexcept;
[[nodiscard]] std::string_view GetPoisoningStatusName(PoisoningStatus status) noexcept;

/// @brief Validate domain name
[[nodiscard]] bool IsValidDomainName(const std::string& domain);

/// @brief Parse DNS response
[[nodiscard]] std::vector<std::string> ParseDNSResponse(
    const std::vector<uint8_t>& response);

/// @brief Get DNS record type from query type ID
[[nodiscard]] DNSRecordType GetRecordTypeFromId(uint16_t typeId);

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_DNS_ENABLE_SECURE(provider) \
    ::ShadowStrike::Privacy::DNSLeakProtection::Instance().EnableSecureDns(provider)

#define SS_DNS_CHECK_LEAKS() \
    ::ShadowStrike::Privacy::DNSLeakProtection::Instance().CheckForLeaks()

#define SS_DNS_RESOLVE(domain) \
    ::ShadowStrike::Privacy::DNSLeakProtection::Instance().ResolveDomain(domain)

#define SS_DNS_IS_SECURE() \
    ::ShadowStrike::Privacy::DNSLeakProtection::Instance().IsSecureDnsEnabled()
