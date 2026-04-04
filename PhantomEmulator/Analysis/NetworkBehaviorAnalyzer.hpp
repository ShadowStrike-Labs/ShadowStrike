/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Phantom {

// ============================================================================
// Network Connection Record
// ============================================================================

struct NetworkConnection {
    std::string remoteAddr;
    uint16_t    remotePort       = 0;
    std::string protocol;         // "tcp", "udp", "http", "https", "dns"
    uint64_t    bytesSent        = 0;
    uint64_t    bytesReceived    = 0;
    uint32_t    connectionCount  = 0;
    uint64_t    firstSeen        = 0;  // Instruction count
    uint64_t    lastSeen         = 0;
    bool        isBeaconing      = false;
    float       suspiciousness   = 0.0f;
};

// ============================================================================
// Network Alert
// ============================================================================

struct NetworkAlert {
    std::string type;         // "c2_beaconing", "dga", "exfiltration", …
    std::string description;
    float       severity = 0.0f; // 0.0 – 1.0
    std::string evidence;        // Supporting data
};

// ============================================================================
// Network Event — generic event passed to C2 protocol signature analysis
// ============================================================================

struct NetworkEvent {
    std::string remoteAddr;
    uint16_t    remotePort     = 0;
    std::string protocol;          // "tcp", "udp", "http", "https", "dns"
    std::string httpMethod;        // "GET", "POST", etc. (HTTP events only)
    std::string httpPath;          // URL path component
    std::string httpHost;          // Host header value
    std::string userAgent;
    std::string dnsQueryDomain;    // Domain queried (DNS events only)
    uint16_t    dnsQueryType   = 0; // 1=A, 5=CNAME, 16=TXT, 28=AAAA, etc.
    std::string namedPipePath;     // Named pipe (SMB events only)
    std::string httpContentType;
    std::string httpCookie;
    uint32_t    payloadSize    = 0;
    uint64_t    timestamp      = 0;
    uint32_t    processId      = 0;

    // HTTP headers as flat key-value pairs (cap enforced by caller)
    std::vector<std::pair<std::string, std::string>> httpHeaders;
};

// ============================================================================
// C2 Detection Result
// ============================================================================

struct C2DetectionResult {
    bool        detected           = false;
    std::string frameworkName;               // "CobaltStrike", "Sliver", etc.
    std::string matchType;                   // "http", "dns", "pipe", "tls"
    float       confidence         = 0.0f;   // 0.0 – 1.0
    std::string evidence;
};

// ============================================================================
// TLS Certificate Info — observed certificate metadata from emulation
// ============================================================================

struct TLSCertInfo {
    std::string commonName;
    std::string issuer;
    uint32_t    validityDays    = 0;
    bool        selfSigned      = false;
    bool        wildcardCN      = false;
    bool        ipAddressCN     = false;
    bool        recentlyCreated = false;    // Certificate issued < 30 days ago
    bool        shortValidity   = false;    // Validity period < 90 days
};

// ============================================================================
// TLS Anomaly Result
// ============================================================================

struct TLSAnomalyResult {
    float anomalyScore     = 0.0f;   // 0.0 – 1.0
    bool  selfSignedCert   = false;
    bool  tooShortValidity = false;
    bool  suspiciousCN     = false;
    bool  knownC2Issuer    = false;
    bool  certAgeTooNew    = false;
};

// ============================================================================
// JA3 / JA3S Fingerprint
// ============================================================================

struct JA3Fingerprint {
    std::string clientHash;     // MD5 hex of TLS ClientHello parameters
    std::string serverHash;     // MD5 hex of TLS ServerHello parameters
    bool        knownMalicious = false;
};

// ============================================================================
// JA3 Match Result
// ============================================================================

struct JA3MatchResult {
    bool        matched        = false;
    std::string hash;
    std::string malwareFamily;
    float       confidence     = 0.0f;
};

// ============================================================================
// HTTP Request — full request representation for header analysis
// ============================================================================

struct HTTPRequest {
    std::string method;
    std::string url;
    std::string host;
    std::string userAgent;
    std::string contentType;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

// ============================================================================
// DNS Query Record — enriched DNS event for advanced analysis
// ============================================================================

struct DNSQueryRecord {
    std::string domain;
    uint16_t    queryType    = 1;   // 1=A, 5=CNAME, 16=TXT, 28=AAAA
    uint64_t    timestamp    = 0;
    uint32_t    cnameDepth   = 0;   // Depth of CNAME chain in response
};

// ============================================================================
// Network Behavior Analyzer
// ============================================================================
// Analyses network behaviour patterns to detect C2 communication, data
// exfiltration, DGA domains, and other network-based threats.
//
// Capabilities:
//   - Beaconing detection (interval jitter analysis)
//   - DGA detection (entropy, consonant ratio, bigram analysis)
//   - Data exfiltration detection (per-connection and global)
//   - DNS tunneling detection (entropy, subdomain cardinality)
//   - Rapid connection detection
//   - C2 protocol signature matching (Cobalt Strike, Sliver, Brute Ratel, Empire)
//   - TLS certificate anomaly detection
//   - JA3/JA3S fingerprint matching
//   - P2P botnet communication pattern detection
//   - HTTP header anomaly analysis
//   - Advanced DNS anomaly analysis (TXT frequency, CNAME depth, query volume)
//
// Thread-safe: designed for single-threaded event-driven analysis.

class NetworkBehaviorAnalyzer {
public:
    explicit NetworkBehaviorAnalyzer(const EmulationConfig& config) noexcept;
    ~NetworkBehaviorAnalyzer() noexcept;

    NetworkBehaviorAnalyzer(const NetworkBehaviorAnalyzer&) = delete;
    NetworkBehaviorAnalyzer& operator=(const NetworkBehaviorAnalyzer&) = delete;
    NetworkBehaviorAnalyzer(NetworkBehaviorAnalyzer&&) noexcept;
    NetworkBehaviorAnalyzer& operator=(NetworkBehaviorAnalyzer&&) noexcept;

    // --- Feed events ---

    void OnConnect(const std::string& addr, uint16_t port,
                   const std::string& protocol) noexcept;
    void OnSend(const std::string& addr, uint16_t port, uint32_t bytes) noexcept;
    void OnReceive(const std::string& addr, uint16_t port, uint32_t bytes) noexcept;
    void OnDnsQuery(const std::string& domain) noexcept;
    void OnHttpRequest(const std::string& method, const std::string& url,
                       const std::string& userAgent) noexcept;

    // --- Extended feed events ---

    void OnTLSCertObserved(const std::string& addr, uint16_t port,
                           const TLSCertInfo& cert) noexcept;
    void OnJA3Observed(const std::string& addr, uint16_t port,
                       const JA3Fingerprint& fingerprint) noexcept;
    void OnNetworkEvent(const NetworkEvent& event) noexcept;
    void OnDnsQueryEx(const DNSQueryRecord& record) noexcept;
    void OnHttpRequestEx(const HTTPRequest& request) noexcept;
    void OnPeerDiscovery(uint32_t processId, const std::string& sourceAddr,
                         const std::vector<std::string>& discoveredAddrs) noexcept;

    // --- Results ---

    [[nodiscard]] const std::vector<NetworkConnection>& GetConnections() const noexcept;
    [[nodiscard]] const std::vector<NetworkAlert>& GetAlerts() const noexcept;
    [[nodiscard]] uint64_t GetTotalBytesSent() const noexcept;
    [[nodiscard]] uint64_t GetTotalBytesReceived() const noexcept;
    [[nodiscard]] bool HasC2Indicators() const noexcept;
    [[nodiscard]] bool HasExfiltrationIndicators() const noexcept;
    [[nodiscard]] std::vector<std::string> GetDGADomains() const noexcept;

    // --- Advanced analysis ---

    [[nodiscard]] C2DetectionResult AnalyzeForC2(const NetworkEvent& event) noexcept;
    [[nodiscard]] TLSAnomalyResult AnalyzeTLSCert(const TLSCertInfo& cert) noexcept;
    [[nodiscard]] JA3MatchResult CheckJA3(const std::string& hash) noexcept;
    [[nodiscard]] float AnalyzePeerBehavior(uint32_t processId) noexcept;
    [[nodiscard]] float AnalyzeHTTPHeaders(const HTTPRequest& request) noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
