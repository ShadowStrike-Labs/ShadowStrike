/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualNetwork.cpp — Network simulation layer
 *
 * All socket operations succeed so the malware fully reveals its C2
 * infrastructure.  No real network traffic is ever emitted.
 *
 * KEY ANALYSIS CAPABILITIES:
 *   - DNS IOC extraction (every resolved hostname is a potential C2 indicator)
 *   - Beaconing detection (regular-interval connections → C2 callback pattern)
 *   - Data exfiltration detection (volume, ratio, fan-out heuristics)
 *   - DGA candidate flagging (Shannon entropy on domain labels)
 *   - Suspicious TLD / cloud-hosted C2 detection
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "VirtualNetwork.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <numeric>
#include <string>
#include <unordered_set>

namespace Phantom::VirtualOS {

// ============================================================================
// Meyers' Singleton
// ============================================================================

VirtualNetwork& VirtualNetwork::Instance() noexcept {
    static VirtualNetwork instance;
    return instance;
}

// ============================================================================
// Initialization / Reset
// ============================================================================

void VirtualNetwork::Initialize(const EmulationConfig& config) noexcept {
    std::unique_lock lock(m_mutex);
    if (m_initialized) return;

    m_sockets.clear();
    m_dnsQueries.clear();
    m_httpRequests.clear();
    m_userAgents.clear();
    m_dnsCache.clear();

    m_nextSocketId = 1;
    m_nextDnsIP    = 1;
    m_hostname     = "DESKTOP-A7B3CF9";

    m_initialized = true;
}

void VirtualNetwork::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_sockets.clear();
    m_dnsQueries.clear();
    m_httpRequests.clear();
    m_userAgents.clear();
    m_dnsCache.clear();
    m_nextSocketId = 1;
    m_nextDnsIP    = 1;
    m_hostname.clear();
    m_initialized = false;
}

// ============================================================================
// Socket Operations
// ============================================================================

uint32_t VirtualNetwork::CreateSocket(uint16_t af, uint16_t type, uint16_t protocol) noexcept {
    std::unique_lock lock(m_mutex);
    if (m_sockets.size() >= kMaxSockets) return 0;

    SocketInfo si{};
    si.id            = m_nextSocketId++;
    si.addressFamily = af;
    si.socketType    = type;
    si.protocol      = protocol;
    si.state         = SocketState::Created;
    si.localIP       = "0.0.0.0";
    si.localPort     = 0;

    uint32_t id = si.id;
    m_sockets.emplace(id, std::move(si));
    return id;
}

bool VirtualNetwork::CloseSocket(uint32_t socketId) noexcept {
    std::unique_lock lock(m_mutex);
    auto it = m_sockets.find(socketId);
    if (it == m_sockets.end()) return false;

    it->second.state = SocketState::Closed;
    return true;
}

bool VirtualNetwork::Connect(uint32_t socketId, std::string_view ip, uint16_t port) noexcept {
    std::unique_lock lock(m_mutex);
    auto it = m_sockets.find(socketId);
    if (it == m_sockets.end()) return false;

    auto& sock = it->second;
    if (sock.state == SocketState::Closed) return false;

    sock.remoteIP   = std::string(ip);
    sock.remotePort = port;
    sock.state      = SocketState::Connected;

    // Assign an ephemeral local port if not already bound
    if (sock.localPort == 0) {
        sock.localIP   = "192.168.1.105";
        sock.localPort = static_cast<uint16_t>(49152 + (socketId % 16384));
    }
    return true;
}

bool VirtualNetwork::Bind(uint32_t socketId, std::string_view ip, uint16_t port) noexcept {
    std::unique_lock lock(m_mutex);
    auto it = m_sockets.find(socketId);
    if (it == m_sockets.end()) return false;

    auto& sock = it->second;
    if (sock.state != SocketState::Created) return false;

    sock.localIP   = std::string(ip);
    sock.localPort = port;
    sock.state     = SocketState::Bound;
    return true;
}

bool VirtualNetwork::Listen(uint32_t socketId) noexcept {
    std::unique_lock lock(m_mutex);
    auto it = m_sockets.find(socketId);
    if (it == m_sockets.end()) return false;

    auto& sock = it->second;
    if (sock.state != SocketState::Bound) return false;

    sock.state = SocketState::Listening;
    return true;
}

std::optional<uint32_t> VirtualNetwork::Accept(uint32_t socketId) noexcept {
    std::unique_lock lock(m_mutex);
    auto it = m_sockets.find(socketId);
    if (it == m_sockets.end()) return std::nullopt;

    auto& listener = it->second;
    if (listener.state != SocketState::Listening) return std::nullopt;
    if (m_sockets.size() >= kMaxSockets) return std::nullopt;

    // Create a new connected socket representing the accepted connection
    SocketInfo accepted{};
    accepted.id            = m_nextSocketId++;
    accepted.addressFamily = listener.addressFamily;
    accepted.socketType    = listener.socketType;
    accepted.protocol      = listener.protocol;
    accepted.state         = SocketState::Connected;
    accepted.localIP       = listener.localIP;
    accepted.localPort     = listener.localPort;
    accepted.remoteIP      = "10.0.1.50";  // Simulated client
    accepted.remotePort    = static_cast<uint16_t>(40000 + (accepted.id % 10000));

    uint32_t newId = accepted.id;
    m_sockets.emplace(newId, std::move(accepted));
    return newId;
}

uint32_t VirtualNetwork::Send(uint32_t socketId, uint32_t size) noexcept {
    std::unique_lock lock(m_mutex);
    auto it = m_sockets.find(socketId);
    if (it == m_sockets.end()) return 0;

    auto& sock = it->second;
    if (sock.state != SocketState::Connected) return 0;

    // Cap single send to 64 KB to prevent unbounded tracking
    uint32_t actual = std::min(size, static_cast<uint32_t>(64 * 1024));
    sock.bytesSent += actual;
    sock.sendCount++;
    sock.sendTimestamps.push_back(sock.sendCount); // ordinal as proxy timestamp
    return actual;
}

uint32_t VirtualNetwork::Recv(uint32_t socketId, uint32_t /*requestedSize*/) noexcept {
    std::unique_lock lock(m_mutex);
    auto it = m_sockets.find(socketId);
    if (it == m_sockets.end()) return 0;

    auto& sock = it->second;
    if (sock.state != SocketState::Connected) return 0;

    // Simulate "connection closed / no response" — return 0 bytes
    sock.recvCount++;
    return 0;
}

// ============================================================================
// DNS Resolution
// ============================================================================
// Each unique hostname maps to a sequential IP in 10.0.0.0/8.
// Cached so repeated lookups return the same address.

std::string VirtualNetwork::ResolveDns(std::string_view hostname) noexcept {
    std::unique_lock lock(m_mutex);

    if (hostname.empty()) return "";

    // Hostname normalization: lower-case copy, capped at 255 chars
    std::string normalized;
    const size_t len = std::min(hostname.size(), static_cast<size_t>(255));
    normalized.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        normalized.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(hostname[i]))));
    }

    // Check cache
    auto cacheIt = m_dnsCache.find(normalized);
    if (cacheIt != m_dnsCache.end()) {
        // Still record the query for IOC tracking
        if (m_dnsQueries.size() < kMaxDnsQueries) {
            DnsQueryRecord rec{};
            rec.hostname   = normalized;
            rec.resolvedIP = cacheIt->second;
            rec.timestamp  = static_cast<uint64_t>(m_dnsQueries.size());
            m_dnsQueries.push_back(std::move(rec));
        }
        return cacheIt->second;
    }

    // Allocate new IP: 10.0.0.x  →  10.x.y.z for > 254 entries
    uint32_t seq = m_nextDnsIP++;
    uint8_t  a   = static_cast<uint8_t>((seq >> 16) & 0xFF);
    uint8_t  b   = static_cast<uint8_t>((seq >> 8)  & 0xFF);
    uint8_t  c   = static_cast<uint8_t>(seq & 0xFF);
    if (c == 0) c = 1; // Avoid .0 addresses

    std::string ip = "10." + std::to_string(a) + "."
                           + std::to_string(b) + "."
                           + std::to_string(c);

    m_dnsCache[normalized] = ip;

    if (m_dnsQueries.size() < kMaxDnsQueries) {
        DnsQueryRecord rec{};
        rec.hostname   = normalized;
        rec.resolvedIP = ip;
        rec.timestamp  = static_cast<uint64_t>(m_dnsQueries.size());
        m_dnsQueries.push_back(std::move(rec));
    }

    return ip;
}

std::string VirtualNetwork::GetHostname() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_hostname;
}

// ============================================================================
// HTTP Logging
// ============================================================================

void VirtualNetwork::LogHttpRequest(const HttpRequestRecord& record) noexcept {
    std::unique_lock lock(m_mutex);
    if (m_httpRequests.size() < kMaxHttpRequests) {
        m_httpRequests.push_back(record);
    }
}

void VirtualNetwork::LogUserAgent(std::string_view userAgent) noexcept {
    std::unique_lock lock(m_mutex);
    if (userAgent.empty()) return;
    if (m_userAgents.size() >= kMaxUserAgents) return;

    // Deduplicate
    std::string ua(userAgent);
    for (const auto& existing : m_userAgents) {
        if (existing == ua) return;
    }
    m_userAgents.push_back(std::move(ua));
}

// ============================================================================
// Analysis — IOC Extraction
// ============================================================================

std::vector<DnsQueryRecord> VirtualNetwork::GetDnsQueries() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_dnsQueries;
}

std::vector<HttpRequestRecord> VirtualNetwork::GetHttpRequests() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_httpRequests;
}

std::vector<SocketInfo> VirtualNetwork::GetConnections() const noexcept {
    std::shared_lock lock(m_mutex);
    std::vector<SocketInfo> result;
    result.reserve(m_sockets.size());
    for (const auto& [id, sock] : m_sockets) {
        result.push_back(sock);
    }
    return result;
}

NetworkIOC VirtualNetwork::GetNetworkIOCs() const noexcept {
    std::shared_lock lock(m_mutex);

    NetworkIOC ioc{};

    // Collect unique IPs
    std::unordered_set<std::string> ips;
    for (const auto& [id, sock] : m_sockets) {
        if (!sock.remoteIP.empty()) {
            ips.insert(sock.remoteIP);
        }
        ioc.totalBytesSent     += sock.bytesSent;
        ioc.totalBytesReceived += sock.bytesReceived;
        if (sock.state == SocketState::Connected ||
            sock.state == SocketState::Closed) {
            ioc.totalConnections++;
        }
    }
    ioc.uniqueIPs.assign(ips.begin(), ips.end());
    std::sort(ioc.uniqueIPs.begin(), ioc.uniqueIPs.end());

    // Collect unique domains
    std::unordered_set<std::string> domains;
    for (const auto& q : m_dnsQueries) {
        domains.insert(q.hostname);
    }
    ioc.uniqueDomains.assign(domains.begin(), domains.end());
    std::sort(ioc.uniqueDomains.begin(), ioc.uniqueDomains.end());
    ioc.totalDnsQueries = static_cast<uint32_t>(m_dnsQueries.size());

    // Collect unique user agents
    ioc.uniqueUserAgents = m_userAgents;

    // Collect unique URLs from HTTP requests
    std::unordered_set<std::string> urls;
    for (const auto& req : m_httpRequests) {
        std::string url = (req.isSSL ? "https://" : "http://") + req.host;
        if ((req.isSSL && req.port != 443) || (!req.isSSL && req.port != 80)) {
            url += ":" + std::to_string(req.port);
        }
        url += req.path;
        urls.insert(std::move(url));
    }
    ioc.uniqueURLs.assign(urls.begin(), urls.end());
    std::sort(ioc.uniqueURLs.begin(), ioc.uniqueURLs.end());
    ioc.totalHttpRequests = static_cast<uint32_t>(m_httpRequests.size());

    // Run detection algorithms (lock already held, call private helpers)
    ioc.hasBeaconingPattern = DetectBeaconingInternal();
    ioc.hasDataExfiltration = DetectExfiltrationInternal();

    return ioc;
}

// ============================================================================
// Beaconing Detection
// ============================================================================
// A beaconing pattern is identified when ≥4 send events to the same
// IP:port occur at roughly regular intervals (within ±20% jitter).
// We use the ordinal send-count as a time proxy since the emulator
// has no real wall clock during execution.

namespace {

[[nodiscard]] bool HasRegularInterval(const std::vector<uint64_t>& timestamps) noexcept {
    if (timestamps.size() < 4) return false;

    // Compute inter-arrival deltas
    std::vector<uint64_t> deltas;
    deltas.reserve(timestamps.size() - 1);
    for (size_t i = 1; i < timestamps.size(); ++i) {
        if (timestamps[i] > timestamps[i - 1]) {
            deltas.push_back(timestamps[i] - timestamps[i - 1]);
        }
    }
    if (deltas.size() < 3) return false;

    // Compute median delta
    std::vector<uint64_t> sorted = deltas;
    std::sort(sorted.begin(), sorted.end());
    uint64_t median = sorted[sorted.size() / 2];
    if (median == 0) return false;

    // Check if ≥80% of deltas fall within ±20% of the median
    uint64_t lo = median - median / 5;  // median * 0.8
    uint64_t hi = median + median / 5;  // median * 1.2
    uint32_t inRange = 0;
    for (auto d : deltas) {
        if (d >= lo && d <= hi) ++inRange;
    }

    return (inRange * 100 / deltas.size()) >= 80;
}

} // anonymous namespace

bool VirtualNetwork::DetectBeaconing() const noexcept {
    std::shared_lock lock(m_mutex);
    return DetectBeaconingInternal();
}

// Private: caller must already hold lock
bool VirtualNetwork::DetectBeaconingInternal() const noexcept {
    // Group send timestamps by remote IP:port
    std::unordered_map<std::string, std::vector<uint64_t>> groups;
    for (const auto& [id, sock] : m_sockets) {
        if (sock.remoteIP.empty() || sock.sendTimestamps.empty()) continue;
        std::string key = sock.remoteIP + ":" + std::to_string(sock.remotePort);
        auto& vec = groups[key];
        vec.insert(vec.end(), sock.sendTimestamps.begin(), sock.sendTimestamps.end());
    }

    for (auto& [key, ts] : groups) {
        std::sort(ts.begin(), ts.end());
        if (HasRegularInterval(ts)) return true;
    }
    return false;
}

// ============================================================================
// Data Exfiltration Detection
// ============================================================================
// Three heuristics:
//   1. >10 MB sent to any single IP
//   2. send/recv ratio >10:1 for any connection
//   3. >1 MB sent to ≥3 distinct IPs

bool VirtualNetwork::DetectExfiltration() const noexcept {
    std::shared_lock lock(m_mutex);
    return DetectExfiltrationInternal();
}

bool VirtualNetwork::DetectExfiltrationInternal() const noexcept {
    constexpr uint64_t kSingleIPThreshold = 10ULL * 1024 * 1024; // 10 MB
    constexpr uint64_t kFanOutThreshold   = 1ULL  * 1024 * 1024; // 1 MB
    constexpr uint32_t kFanOutMinIPs      = 3;
    constexpr uint64_t kRatioThreshold    = 10;

    // Aggregate bytes per remote IP
    std::unordered_map<std::string, uint64_t> sentPerIP;
    std::unordered_map<std::string, uint64_t> recvPerIP;

    for (const auto& [id, sock] : m_sockets) {
        if (sock.remoteIP.empty()) continue;
        sentPerIP[sock.remoteIP] += sock.bytesSent;
        recvPerIP[sock.remoteIP] += sock.bytesReceived;
    }

    uint32_t highVolumeTargets = 0;
    for (const auto& [ip, sent] : sentPerIP) {
        // Heuristic 1: single-target volume
        if (sent > kSingleIPThreshold) return true;

        // Heuristic 2: send/recv ratio
        uint64_t recv = 0;
        auto it = recvPerIP.find(ip);
        if (it != recvPerIP.end()) recv = it->second;
        if (recv > 0 && sent / recv > kRatioThreshold) return true;
        // recv==0 is normal in the emulator (Recv always returns 0).
        // Only flag if the volume itself is significant (>1 MB with no response).
        if (recv == 0 && sent > kFanOutThreshold) return true;

        // Heuristic 3: fan-out
        if (sent > kFanOutThreshold) highVolumeTargets++;
    }

    if (highVolumeTargets >= kFanOutMinIPs) return true;

    return false;
}

// ============================================================================
// Domain Suspiciousness Analysis (private)
// ============================================================================
// Flags domains that are commonly associated with C2 infrastructure.

bool VirtualNetwork::IsSuspiciousDomain(std::string_view hostname) const noexcept {
    if (hostname.empty()) return false;

    // Normalize to lower case for comparison
    std::string h;
    h.reserve(hostname.size());
    for (char c : hostname) {
        h.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }

    // 1. Suspicious TLDs
    static constexpr std::string_view kSuspiciousTLDs[] = {
        ".onion", ".bit", ".bazar", ".coin", ".lib",
        ".emc",   ".chan", ".oz",
    };
    for (const auto& tld : kSuspiciousTLDs) {
        if (h.size() > tld.size() &&
            h.compare(h.size() - tld.size(), tld.size(), tld) == 0) {
            return true;
        }
    }

    // 2. Cloud hosting commonly abused by C2 frameworks
    static constexpr std::string_view kSuspiciousSuffixes[] = {
        ".cloudfront.net",
        ".amazonaws.com",
        ".azurewebsites.net",
        ".firebaseapp.com",
        ".appspot.com",
        ".herokuapp.com",
        ".ngrok.io",
        ".ngrok.app",
        ".serveo.net",
        ".portmap.host",
    };
    for (const auto& suffix : kSuspiciousSuffixes) {
        if (h.size() > suffix.size() &&
            h.compare(h.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
    }

    // 3. IP-like hostname (e.g., "192.168.1.1" used directly)
    bool allDigitsOrDots = true;
    for (char c : h) {
        if (c != '.' && (c < '0' || c > '9')) {
            allDigitsOrDots = false;
            break;
        }
    }
    if (allDigitsOrDots && h.find('.') != std::string::npos) return true;

    // 4. Very long hostname (>50 chars) — possible DGA or encoding
    if (h.size() > 50) return true;

    // 5. DGA detection: compute entropy of the leftmost label
    auto dotPos = h.find('.');
    std::string_view label = (dotPos != std::string::npos)
                              ? std::string_view(h.data(), dotPos)
                              : std::string_view(h);
    if (label.size() >= 6 && ComputeDomainEntropy(label) > 3.5) {
        return true;
    }

    return false;
}

double VirtualNetwork::ComputeDomainEntropy(std::string_view label) const noexcept {
    if (label.empty()) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (unsigned char c : label) {
        freq[c]++;
    }

    double entropy = 0.0;
    const double n = static_cast<double>(label.size());
    for (auto count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / n;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

} // namespace Phantom::VirtualOS
