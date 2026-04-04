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
// Network Behavior Analyzer
// ============================================================================
// Analyses network behaviour patterns to detect C2 communication, data
// exfiltration, DGA domains, and other network-based threats.
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

    // --- Results ---

    [[nodiscard]] const std::vector<NetworkConnection>& GetConnections() const noexcept;
    [[nodiscard]] const std::vector<NetworkAlert>& GetAlerts() const noexcept;
    [[nodiscard]] uint64_t GetTotalBytesSent() const noexcept;
    [[nodiscard]] uint64_t GetTotalBytesReceived() const noexcept;
    [[nodiscard]] bool HasC2Indicators() const noexcept;
    [[nodiscard]] bool HasExfiltrationIndicators() const noexcept;
    [[nodiscard]] std::vector<std::string> GetDGADomains() const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
