/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualNetwork.hpp — Network simulation layer
 *
 * Centralized backing store for all emulated network operations.
 *   - Socket lifecycle management (create / connect / send / recv / close)
 *   - DNS resolution simulation with domain IOC extraction
 *   - HTTP request/response logging
 *   - Beaconing detection  (regular-interval C2 callbacks)
 *   - Data exfiltration detection (volume / ratio / fan-out)
 *
 * All connections succeed so the malware fully exposes its C2 chain
 * before detonation scoring.  No real network traffic is ever emitted.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <chrono>

namespace Phantom::VirtualOS {

// ============================================================================
// Socket State Machine
// ============================================================================

enum class SocketState : uint8_t {
    Created,
    Bound,
    Listening,
    Connected,
    Closed,
};

// ============================================================================
// Data Structures
// ============================================================================

struct SocketInfo {
    uint32_t    id;
    uint16_t    addressFamily;   // AF_INET = 2, AF_INET6 = 23
    uint16_t    socketType;      // SOCK_STREAM = 1, SOCK_DGRAM = 2
    uint16_t    protocol;        // IPPROTO_TCP = 6, IPPROTO_UDP = 17
    SocketState state = SocketState::Created;

    // Connection endpoints
    std::string remoteIP;
    uint16_t    remotePort = 0;
    std::string localIP;
    uint16_t    localPort  = 0;

    // Traffic statistics
    uint64_t    bytesSent     = 0;
    uint64_t    bytesReceived = 0;
    uint32_t    sendCount     = 0;
    uint32_t    recvCount     = 0;

    // Timestamps for beaconing analysis (instruction count at each send)
    std::vector<uint64_t> sendTimestamps;
};

struct DnsQueryRecord {
    std::string hostname;
    std::string resolvedIP;        // Always 10.0.0.x (sequential)
    uint64_t    timestamp;         // Instruction count
};

struct HttpRequestRecord {
    std::string method;            // GET, POST, PUT, etc.
    std::string host;
    uint16_t    port;
    std::string path;
    std::string userAgent;
    std::string headers;
    uint32_t    bodySize;
    uint64_t    timestamp;
    bool        isSSL;
};

// IOC summary produced at the end of an emulation session.
struct NetworkIOC {
    std::vector<std::string> uniqueIPs;
    std::vector<std::string> uniqueDomains;
    std::vector<std::string> uniqueUserAgents;
    std::vector<std::string> uniqueURLs;
    uint64_t totalBytesSent     = 0;
    uint64_t totalBytesReceived = 0;
    uint32_t totalConnections   = 0;
    uint32_t totalDnsQueries    = 0;
    uint32_t totalHttpRequests  = 0;
    bool     hasBeaconingPattern  = false;
    bool     hasDataExfiltration  = false;
};

// ============================================================================
// VirtualNetwork — Singleton
// ============================================================================

class VirtualNetwork {
public:
    [[nodiscard]] static VirtualNetwork& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // === Socket Operations ===
    [[nodiscard]] uint32_t CreateSocket(uint16_t af, uint16_t type, uint16_t protocol) noexcept;
    bool CloseSocket(uint32_t socketId) noexcept;
    bool Connect(uint32_t socketId, std::string_view ip, uint16_t port) noexcept;
    bool Bind(uint32_t socketId, std::string_view ip, uint16_t port) noexcept;
    bool Listen(uint32_t socketId) noexcept;
    [[nodiscard]] std::optional<uint32_t> Accept(uint32_t socketId) noexcept;

    // Send/Recv — track sizes only, never transmit real data
    uint32_t Send(uint32_t socketId, uint32_t size) noexcept;
    uint32_t Recv(uint32_t socketId, uint32_t requestedSize) noexcept;

    // === DNS ===
    [[nodiscard]] std::string ResolveDns(std::string_view hostname) noexcept;
    [[nodiscard]] std::string GetHostname() const noexcept;

    // === HTTP Logging ===
    void LogHttpRequest(const HttpRequestRecord& record) noexcept;
    void LogUserAgent(std::string_view userAgent) noexcept;

    // === Analysis ===
    [[nodiscard]] NetworkIOC  GetNetworkIOCs()  const noexcept;
    [[nodiscard]] std::vector<DnsQueryRecord>    GetDnsQueries()   const noexcept;
    [[nodiscard]] std::vector<HttpRequestRecord> GetHttpRequests() const noexcept;
    [[nodiscard]] std::vector<SocketInfo>         GetConnections()  const noexcept;

    // === Beaconing Detection ===
    [[nodiscard]] bool DetectBeaconing() const noexcept;

    // === Data Exfiltration Detection ===
    [[nodiscard]] bool DetectExfiltration() const noexcept;

private:
    VirtualNetwork() noexcept = default;
    ~VirtualNetwork() noexcept = default;
    VirtualNetwork(const VirtualNetwork&) = delete;
    VirtualNetwork& operator=(const VirtualNetwork&) = delete;

    [[nodiscard]] bool IsSuspiciousDomain(std::string_view hostname) const noexcept;
    [[nodiscard]] double ComputeDomainEntropy(std::string_view label) const noexcept;

    // Lock-free internal variants called from GetNetworkIOCs() which
    // already holds the shared lock.
    [[nodiscard]] bool DetectBeaconingInternal() const noexcept;
    [[nodiscard]] bool DetectExfiltrationInternal() const noexcept;

    mutable std::shared_mutex m_mutex;
    std::unordered_map<uint32_t, SocketInfo> m_sockets;
    std::vector<DnsQueryRecord>    m_dnsQueries;
    std::vector<HttpRequestRecord> m_httpRequests;
    std::vector<std::string>       m_userAgents;

    // hostname → resolved IP cache
    std::unordered_map<std::string, std::string> m_dnsCache;

    uint32_t    m_nextSocketId = 1;
    uint32_t    m_nextDnsIP    = 1;    // For 10.0.0.x sequential IPs
    std::string m_hostname;
    bool        m_initialized  = false;

    static constexpr uint32_t kMaxSockets      = 4096;
    static constexpr uint32_t kMaxDnsQueries   = 10000;
    static constexpr uint32_t kMaxHttpRequests = 10000;
    static constexpr uint32_t kMaxUserAgents   = 256;
};

} // namespace Phantom::VirtualOS
