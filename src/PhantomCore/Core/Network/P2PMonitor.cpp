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
 * ShadowStrike Core Network - P2P MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file P2PMonitor.cpp
 * @brief Enterprise-grade P2P traffic detection and control engine.
 *
 * This module provides comprehensive detection, monitoring, and control of
 * Peer-to-Peer network traffic including BitTorrent, DHT, eMule, and other
 * decentralized protocols used for both legitimate and malicious purposes.
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Multi-layered protocol detection (magic bytes, patterns, heuristics)
 * - Real-time swarm tracking with LRU eviction
 * - Threat correlation with ThreatIntel integration
 * - Policy enforcement with bandwidth throttling
 * - Callback architecture for event notifications
 *
 * Detection Capabilities:
 * - BitTorrent protocol (TCP/UDP handshakes, 20-byte infohash extraction)
 * - DHT (Mainline/Kademlia bencode parsing)
 * - uTP (Micro Transport Protocol)
 * - PEX (Peer Exchange)
 * - eMule/Kademlia
 * - Gnutella, Direct Connect, IPFS
 *
 * Threat Detection:
 * - P2P botnet communication patterns
 * - Malware distribution via torrents
 * - Cryptominer deployment
 * - Data exfiltration over P2P
 * - Copyright infringement
 *
 * MITRE ATT&CK Coverage:
 * - T1071: Application Layer Protocol
 * - T1090: Proxy (P2P overlay networks)
 * - T1105: Ingress Tool Transfer
 * - T1567: Exfiltration Over Web Service
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "P2PMonitor.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../ThreatIntel/ThreatIntelStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <iphlpapi.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <cstring>
#include <thread>
#include <chrono>
#include <cmath>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // BitTorrent protocol constants
    constexpr uint8_t BITTORRENT_HEADER_BYTE = 0x13;
    const std::array<uint8_t, 10> BITTORRENT_PROTOCOL_STRING = {
        0x42, 0x69, 0x74, 0x54, 0x6F, 0x72, 0x72, 0x65, 0x6E, 0x74  // "BitTorrent"
    };

    // Maximum tracked connections to prevent DoS via memory exhaustion
    constexpr size_t MAX_TRACKED_CONNECTIONS = 50000;

    // DHT bencode magic
    const std::string DHT_QUERY_PREFIX = "d1:";
    const std::string DHT_ANNOUNCE_PREFIX = "d1:ad2:id20:";

    // uTP magic
    constexpr uint8_t UTP_VERSION_1 = 1;
    constexpr uint8_t UTP_TYPE_MASK = 0xF0;
    constexpr uint8_t UTP_ST_DATA = 0x00;
    constexpr uint8_t UTP_ST_FIN = 0x10;
    constexpr uint8_t UTP_ST_STATE = 0x20;
    constexpr uint8_t UTP_ST_RESET = 0x30;
    constexpr uint8_t UTP_ST_SYN = 0x40;

    // eMule magic
    const std::array<uint8_t, 1> EMULE_PROTOCOL_TCP = { 0xE3 };
    const std::array<uint8_t, 1> EMULE_PROTOCOL_UDP = { 0xC5 };
    const std::array<uint8_t, 1> KADEMLIA_MAGIC = { 0xE4 };

    // Gnutella
    const std::string GNUTELLA_CONNECT = "GNUTELLA CONNECT/";
    const std::string GNUTELLA_OK = "GNUTELLA/0.6 200 OK";

    // Client identification (peer ID prefixes)
    struct ClientPrefix {
        std::string prefix;
        P2PApplication app;
        std::string name;
    };

    const std::vector<ClientPrefix> CLIENT_PREFIXES = {
        {"-qB", P2PApplication::QBITTORRENT, "qBittorrent"},
        {"-UT", P2PApplication::UTORRENT, "uTorrent"},
        {"-TR", P2PApplication::TRANSMISSION, "Transmission"},
        {"-DE", P2PApplication::DELUGE, "Deluge"},
        {"-AZ", P2PApplication::VUZE, "Azureus/Vuze"},
        {"-BC", P2PApplication::BITCOMET, "BitComet"},
        {"-TX", P2PApplication::TIXATI, "Tixati"},
        {"-RT", P2PApplication::RTORRENT, "rTorrent"},
        {"-lt", P2PApplication::LIBTORRENT, "libtorrent"},
    };

    // Threat indicators
    constexpr uint32_t SUSPICIOUS_PEER_COUNT = 1000;
    constexpr uint64_t SUSPICIOUS_BANDWIDTH_BPS = 100ULL * 1024 * 1024;  // 100 MB/s
    constexpr double SUSPICIOUS_UPLOAD_RATIO = 10.0;

    // Timeouts
    constexpr uint32_t CONNECTION_TIMEOUT_SEC = 600;  // 10 minutes
    constexpr uint32_t SWARM_TIMEOUT_SEC = 1800;     // 30 minutes
    constexpr uint32_t PEER_ACTIVITY_TIMEOUT_SEC = 300;  // 5 minutes

} // anonymous namespace

// ============================================================================
// INFOHASH IMPLEMENTATION
// ============================================================================

bool InfoHash::operator==(const InfoHash& other) const noexcept {
    return hash == other.hash;
}

size_t InfoHash::Hash::operator()(const InfoHash& ih) const noexcept {
    // FNV-1a over the full 20-byte SHA-1 infohash. The previous implementation
    // packed only the first 8 bytes which let an attacker craft many infohashes
    // that collide in the unordered_map bucket — a hash-table DoS vector when
    // arbitrary peers can announce on the swarm.
    return static_cast<size_t>(
        Utils::HashUtils::Fnv1a64(ih.hash.data(), ih.hash.size()));
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static std::string InfoHashToHex(const std::array<uint8_t, 20>& hash) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

[[nodiscard]] static std::optional<std::array<uint8_t, 20>> HexToInfoHash(const std::string& hex) {
    // Strict 40-char canonical hex. The previous std::stoi-based parser
    // accepted whitespace/sign prefixes inside each 2-char window, allowing
    // the same logical hash to be expressed as multiple distinct strings
    // (e.g. " 1A", "+5") — a cache-poisoning / dedupe-bypass vector for
    // the malicious-hash store and swarm tracker.
    if (hex.length() != 40) return std::nullopt;

    auto fromHex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    std::array<uint8_t, 20> hash{};
    for (size_t i = 0; i < 20; ++i) {
        const int hi = fromHex(hex[i * 2]);
        const int lo = fromHex(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        hash[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return hash;
}

[[nodiscard]] static P2PApplication IdentifyClient(const std::string& peerIdStr) {
    // BitTorrent peer IDs are 20 raw bytes — they may contain NUL or other
    // control characters. Compare the prefix as raw bytes via memcmp so the
    // detection cannot be evaded by embedding NUL inside the slot.
    if (peerIdStr.length() < 3) return P2PApplication::UNKNOWN;

    for (const auto& client : CLIENT_PREFIXES) {
        if (client.prefix.size() <= peerIdStr.size() &&
            std::memcmp(peerIdStr.data(), client.prefix.data(), client.prefix.size()) == 0) {
            return client.app;
        }
    }

    return P2PApplication::UNKNOWN;
}

[[nodiscard]] static std::string ExtractClientVersion(const std::string& peerIdStr) {
    // Example: "-qB4250-" -> "4.2.5.0"
    // Peer ID is 20 raw bytes. Use byte-level access (unsigned char) so a
    // negative char value cannot trip std::isdigit's UB when compiled with
    // signed-char defaults.
    if (peerIdStr.length() < 8) return "Unknown";

    try {
        std::string version;
        for (size_t i = 3; i < 7 && i < peerIdStr.size(); ++i) {
            const unsigned char c = static_cast<unsigned char>(peerIdStr[i]);
            if (c >= '0' && c <= '9') {
                version += static_cast<char>(c);
                version += '.';
            }
        }
        if (!version.empty() && version.back() == '.') {
            version.pop_back();
        }
        return version.empty() ? "Unknown" : version;
    } catch (...) {
        return "Unknown";
    }
}

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

P2PMonitorConfig P2PMonitorConfig::CreateDefault() noexcept {
    P2PMonitorConfig config;
    config.enabled = true;
    config.policy = P2PPolicy::MONITOR;
    config.detectBitTorrent = true;
    config.detectDHT = true;
    config.detecteMule = true;
    config.detectOtherP2P = true;
    config.trackInfoHashes = true;
    config.resolveMetadata = true;
    config.trackPeers = true;
    config.checkMaliciousHashes = true;
    config.detectBotnets = true;
    config.detectDataExfiltration = true;
    config.bandwidthLimitBps = P2PMonitorConstants::DEFAULT_BANDWIDTH_LIMIT_BPS;
    config.connectionLimit = P2PMonitorConstants::DEFAULT_CONNECTION_LIMIT;
    config.blockMalicious = true;
    config.alertOnDetection = true;
    config.alertOnMalicious = true;
    config.alertOnPolicyViolation = true;
    config.logAllConnections = false;
    config.logDetectionsOnly = true;
    return config;
}

P2PMonitorConfig P2PMonitorConfig::CreateCorporate() noexcept {
    P2PMonitorConfig config;
    config.enabled = true;
    config.policy = P2PPolicy::BLOCK_ALL;
    config.detectBitTorrent = true;
    config.detectDHT = true;
    config.detecteMule = true;
    config.detectOtherP2P = true;
    config.trackInfoHashes = true;
    config.resolveMetadata = false;  // Don't resolve, just block
    config.trackPeers = false;
    config.checkMaliciousHashes = true;
    config.detectBotnets = true;
    config.detectDataExfiltration = true;
    config.bandwidthLimitBps = 0;  // Block, don't throttle
    config.connectionLimit = 0;
    config.blockMalicious = true;
    config.alertOnDetection = true;
    config.alertOnMalicious = true;
    config.alertOnPolicyViolation = true;
    config.logAllConnections = true;
    config.logDetectionsOnly = false;
    return config;
}

P2PMonitorConfig P2PMonitorConfig::CreateThrottle() noexcept {
    P2PMonitorConfig config;
    config.enabled = true;
    config.policy = P2PPolicy::THROTTLE;
    config.detectBitTorrent = true;
    config.detectDHT = true;
    config.detecteMule = true;
    config.detectOtherP2P = true;
    config.trackInfoHashes = true;
    config.resolveMetadata = true;
    config.trackPeers = true;
    config.checkMaliciousHashes = true;
    config.detectBotnets = true;
    config.detectDataExfiltration = true;
    config.bandwidthLimitBps = 1024 * 1024;  // 1 MB/s limit
    config.connectionLimit = 50;
    config.blockMalicious = true;
    config.alertOnDetection = false;
    config.alertOnMalicious = true;
    config.alertOnPolicyViolation = true;
    config.logAllConnections = false;
    config.logDetectionsOnly = true;
    return config;
}

P2PMonitorConfig P2PMonitorConfig::CreateMonitorOnly() noexcept {
    P2PMonitorConfig config;
    config.enabled = true;
    config.policy = P2PPolicy::ALERT_ONLY;
    config.detectBitTorrent = true;
    config.detectDHT = true;
    config.detecteMule = true;
    config.detectOtherP2P = true;
    config.trackInfoHashes = true;
    config.resolveMetadata = true;
    config.trackPeers = true;
    config.checkMaliciousHashes = true;
    config.detectBotnets = true;
    config.detectDataExfiltration = true;
    config.bandwidthLimitBps = P2PMonitorConstants::DEFAULT_BANDWIDTH_LIMIT_BPS;
    config.connectionLimit = P2PMonitorConstants::DEFAULT_CONNECTION_LIMIT;
    config.blockMalicious = false;  // Alert only, don't block
    config.alertOnDetection = true;
    config.alertOnMalicious = true;
    config.alertOnPolicyViolation = true;
    config.logAllConnections = true;
    config.logDetectionsOnly = false;
    return config;
}

void P2PMonitorStatistics::Reset() noexcept {
    totalConnectionsChecked = 0;
    p2pConnectionsDetected = 0;
    bittorrentConnections = 0;
    dhtQueries = 0;
    emuleConnections = 0;
    otherP2PConnections = 0;
    activeSwarms = 0;
    totalPeersTracked = 0;
    uniqueInfoHashes = 0;
    totalBytesP2P = 0;
    bytesDownloaded = 0;
    bytesUploaded = 0;
    maliciousTorrents = 0;
    botnetActivityDetected = 0;
    policyViolations = 0;
    connectionsBlocked = 0;
    connectionsThrottled = 0;
    alertsGenerated = 0;
    qbittorrentDetected = 0;
    utorrentDetected = 0;
    transmissionDetected = 0;
    otherClientsDetected = 0;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class P2PMonitorImpl final {
public:
    P2PMonitorImpl() = default;
    ~P2PMonitorImpl() = default;

    // Delete copy/move
    P2PMonitorImpl(const P2PMonitorImpl&) = delete;
    P2PMonitorImpl& operator=(const P2PMonitorImpl&) = delete;
    P2PMonitorImpl(P2PMonitorImpl&&) = delete;
    P2PMonitorImpl& operator=(P2PMonitorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const P2PMonitorConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;
            m_initialized = true;

            SS_LOG_INFO(L"Network", L"P2PMonitor initialized (policy=%d, detectBT=%d, detectDHT=%d)",
                static_cast<int>(config.policy), static_cast<int>(config.detectBitTorrent), static_cast<int>(config.detectDHT));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"P2PMonitor initialization failed: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_initialized) {
                SS_LOG_ERROR(L"Network", L"P2PMonitor: Cannot start - not initialized");
                return false;
            }

            if (m_running) {
                SS_LOG_WARN(L"Network", L"P2PMonitor: Already running");
                return true;
            }

            m_running = true;

            // Start monitoring thread
            m_monitorThread = std::thread([this]() { MonitoringLoop(); });

            SS_LOG_INFO(L"Network", L"P2PMonitor started");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"P2PMonitor start failed: %hs", e.what());
            m_running = false;
            return false;
        }
    }

    void Stop() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_running) {
                return;
            }

            m_running = false;

            lock.unlock();

            // Wait for monitoring thread
            if (m_monitorThread.joinable()) {
                m_monitorThread.join();
            }

            SS_LOG_INFO(L"Network", L"P2PMonitor stopped");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"P2PMonitor stop failed: %hs", e.what());
        }
    }

    void Shutdown() noexcept {
        try {
            Stop();

            std::unique_lock lock(m_mutex);

            m_connections.clear();
            m_swarms.clear();
            m_swarmConnections.clear();
            m_peers.clear();
            m_dhtNodes.clear();
            m_maliciousHashes.clear();

            m_detectionCallbacks.clear();
            m_alertCallbacks.clear();
            m_swarmCallbacks.clear();
            m_torrentCallbacks.clear();
            m_dhtCallbacks.clear();

            m_initialized = false;

            SS_LOG_INFO(L"Network", L"P2PMonitor shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    [[nodiscard]] bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

    // ========================================================================
    // P2P DETECTION
    // ========================================================================

    [[nodiscard]] bool IsP2PTraffic(uint32_t pid) {
        std::shared_lock lock(m_mutex);

        try {
            m_stats.totalConnectionsChecked++;

            // Check if we have any P2P connections for this process
            for (const auto& [connId, conn] : m_connections) {
                if (conn.processId == pid && conn.protocol != P2PProtocol::UNKNOWN) {
                    return true;
                }
            }

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"IsP2PTraffic - Exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<P2PConnection> GetP2PConnections(uint32_t pid) const {
        std::shared_lock lock(m_mutex);
        std::vector<P2PConnection> result;

        try {
            for (const auto& [connId, conn] : m_connections) {
                if (conn.processId == pid && conn.protocol != P2PProtocol::UNKNOWN) {
                    result.push_back(conn);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GetP2PConnections - Exception: %hs", e.what());
        }

        return result;
    }

    [[nodiscard]] std::vector<P2PConnection> GetAllP2PConnections() const {
        std::shared_lock lock(m_mutex);
        std::vector<P2PConnection> result;

        try {
            result.reserve(m_connections.size());
            for (const auto& [connId, conn] : m_connections) {
                if (conn.protocol != P2PProtocol::UNKNOWN) {
                    result.push_back(conn);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GetAllP2PConnections - Exception: %hs", e.what());
        }

        return result;
    }

    [[nodiscard]] P2PProtocol DetectProtocol(std::span<const uint8_t> packet) const {
        try {
            if (packet.empty()) return P2PProtocol::UNKNOWN;

            // BitTorrent TCP handshake
            if (packet.size() >= 20 && packet[0] == BITTORRENT_HEADER_BYTE) {
                if (packet.size() >= 11 &&
                    std::equal(BITTORRENT_PROTOCOL_STRING.begin(),
                              BITTORRENT_PROTOCOL_STRING.end(),
                              packet.begin() + 1)) {
                    return P2PProtocol::BITTORRENT_TCP;
                }
            }

            // DHT (bencode) -- require at least "d1:" prefix plus a known
            // DHT key pattern ("y", "q", "r", "t") to reduce false positives
            // from other bencoded protocols
            if (packet.size() >= 10) {
                std::string prefix(reinterpret_cast<const char*>(packet.data()),
                                  std::min(size_t(3), packet.size()));
                if (prefix == DHT_QUERY_PREFIX) {
                    // Scan for DHT-specific keys: "1:y", "1:q", "1:t", "1:r"
                    std::string_view payload(reinterpret_cast<const char*>(packet.data()),
                                             std::min(packet.size(), size_t(256)));
                    if (payload.find("1:y") != std::string_view::npos ||
                        payload.find("1:q") != std::string_view::npos ||
                        payload.find("1:t") != std::string_view::npos) {
                        return P2PProtocol::DHT;
                    }
                }
            }

            // uTP — verify version nibble (low nibble of byte 0) is 1,
            // type nibble is one of the documented values, and extension byte
            // (byte 1) is 0-2 to reduce false positives on non-P2P traffic.
            // (Earlier code compared `type >= UTP_ST_DATA` with UTP_ST_DATA == 0,
            // which is a tautology on uint8_t and triggered MSVC C4296.)
            if (packet.size() >= 20) {
                uint8_t ver_type = packet[0];
                uint8_t version = ver_type & 0x0F;
                uint8_t type = ver_type & UTP_TYPE_MASK;
                uint8_t extension = packet[1];
                const bool typeValid =
                    (type == UTP_ST_DATA) || (type == UTP_ST_FIN) ||
                    (type == UTP_ST_STATE) || (type == UTP_ST_RESET) ||
                    (type == UTP_ST_SYN);
                if (version == UTP_VERSION_1 && typeValid && extension <= 2) {
                    // Additional validation: uTP connection_id at bytes 2-3
                    // and timestamp at bytes 4-7 should not all be zero
                    uint16_t connId = (static_cast<uint16_t>(packet[2]) << 8) | packet[3];
                    uint32_t timestamp = (static_cast<uint32_t>(packet[4]) << 24) |
                                         (static_cast<uint32_t>(packet[5]) << 16) |
                                         (static_cast<uint32_t>(packet[6]) << 8) |
                                         static_cast<uint32_t>(packet[7]);
                    if (connId != 0 || timestamp != 0) {
                        return P2PProtocol::UTP;
                    }
                }
            }

            // eMule TCP packet header: [0xE3] [size:4 LE] [opcode:1] [...]
            // We require the declared packet length to be at least 1 (opcode)
            // and not absurdly large (eMule frames cap at 1 MiB in practice),
            // otherwise the single magic byte 0xE3 produced massive false
            // positives across unrelated TCP traffic.
            if (packet.size() >= 6 && packet[0] == EMULE_PROTOCOL_TCP[0]) {
                const uint32_t emuleLen =
                    static_cast<uint32_t>(packet[1]) |
                    (static_cast<uint32_t>(packet[2]) << 8) |
                    (static_cast<uint32_t>(packet[3]) << 16) |
                    (static_cast<uint32_t>(packet[4]) << 24);
                if (emuleLen >= 1 && emuleLen <= (1u << 20)) {
                    return P2PProtocol::EMULE_TCP;
                }
            }

            // eMule UDP / Kademlia: require at least header + opcode and a
            // payload byte before declaring a match.
            if (packet.size() >= 3 && packet[0] == EMULE_PROTOCOL_UDP[0]) {
                return P2PProtocol::EMULE_UDP;
            }

            if (packet.size() >= 3 && packet[0] == KADEMLIA_MAGIC[0]) {
                return P2PProtocol::KADEMLIA;
            }

            // Gnutella
            if (packet.size() >= GNUTELLA_CONNECT.length()) {
                std::string prefix(reinterpret_cast<const char*>(packet.data()),
                                  GNUTELLA_CONNECT.length());
                if (prefix == GNUTELLA_CONNECT || prefix.find("GNUTELLA") == 0) {
                    return P2PProtocol::GNUTELLA;
                }
            }

            return P2PProtocol::UNKNOWN;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectProtocol - Exception: %hs", e.what());
            return P2PProtocol::UNKNOWN;
        }
    }

    // ========================================================================
    // SWARM MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::vector<SwarmInfo> GetActiveSwarms() const {
        std::shared_lock lock(m_mutex);
        std::vector<SwarmInfo> result;

        try {
            result.reserve(m_swarms.size());
            for (const auto& [hash, swarm] : m_swarms) {
                result.push_back(swarm);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GetActiveSwarms - Exception: %hs", e.what());
        }

        return result;
    }

    [[nodiscard]] std::optional<SwarmInfo> GetSwarm(const InfoHash& infoHash) const {
        std::shared_lock lock(m_mutex);

        try {
            auto it = m_swarms.find(infoHash);
            if (it != m_swarms.end()) {
                return it->second;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GetSwarm - Exception: %hs", e.what());
        }

        return std::nullopt;
    }

    [[nodiscard]] std::optional<SwarmInfo> GetSwarm(const std::string& infoHashHex) const {
        try {
            auto hashBytes = HexToInfoHash(infoHashHex);
            if (!hashBytes) return std::nullopt;

            InfoHash ih;
            ih.hash = *hashBytes;
            ih.hexString = infoHashHex;

            return GetSwarm(ih);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GetSwarm(hex) - Exception: %hs", e.what());
            return std::nullopt;
        }
    }

    // ========================================================================
    // TORRENT LOOKUP
    // ========================================================================

    [[nodiscard]] std::optional<TorrentInfo> LookupTorrent(const InfoHash& infoHash) const {
        std::shared_lock lock(m_mutex);

        try {
            // Check if we have metadata in swarm tracker
            auto swarmIt = m_swarms.find(infoHash);
            if (swarmIt != m_swarms.end() && swarmIt->second.torrentInfo) {
                return swarmIt->second.torrentInfo;
            }

            // No metadata available locally — torrent metadata resolution
            // is performed asynchronously via DHT/tracker scraping by the
            // monitoring thread. Callers should register a TorrentCallback
            // to be notified when metadata becomes available.
            return std::nullopt;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"LookupTorrent - Exception: %hs", e.what());
            return std::nullopt;
        }
    }

    [[nodiscard]] bool IsKnownMaliciousLocked(const InfoHash& infoHash) const {
        try {
            // Check local malicious hash database (populated via AddMaliciousHash
            // and ThreatIntel integration through callback wiring)
            if (m_maliciousHashes.find(infoHash) != m_maliciousHashes.end()) {
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"IsKnownMaliciousLocked - Exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool IsKnownMalicious(const InfoHash& infoHash) const {
        std::shared_lock lock(m_mutex);
        return IsKnownMaliciousLocked(infoHash);
    }

    void AddMaliciousHash(const InfoHash& infoHash, const std::string& reason) {
        std::unique_lock lock(m_mutex);

        try {
            // Sanitize reason for log injection (CRLF) and clamp size.
            // The reason originates from external feeds / orchestrator and
            // is logged below; raw newlines would let an attacker forge
            // additional log lines.
            std::string safeReason;
            safeReason.reserve(std::min<size_t>(reason.size(), 256));
            for (size_t i = 0; i < reason.size() && safeReason.size() < 256; ++i) {
                const unsigned char c = static_cast<unsigned char>(reason[i]);
                if (c == '\r' || c == '\n' || c == '\t') {
                    safeReason += ' ';
                } else if (c < 0x20 || c == 0x7F) {
                    safeReason += '?';
                } else {
                    safeReason += static_cast<char>(c);
                }
            }

            m_maliciousHashes[infoHash] = safeReason;

            // This is informational policy data, not a fatal error — use INFO.
            SS_LOG_INFO(L"Network", L"Marked infohash as malicious: %hs (reason: %hs)",
                infoHash.hexString.c_str(), safeReason.c_str());

            m_stats.maliciousTorrents++;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AddMaliciousHash - Exception: %hs", e.what());
        }
    }

    // ========================================================================
    // DHT MONITORING
    // ========================================================================

    [[nodiscard]] std::optional<DHTInfo> GetDHTInfo(uint32_t pid) const {
        std::shared_lock lock(m_mutex);

        try {
            auto it = m_dhtNodes.find(pid);
            if (it != m_dhtNodes.end()) {
                return it->second;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GetDHTInfo - Exception: %hs", e.what());
        }

        return std::nullopt;
    }

    // ========================================================================
    // TRAFFIC ANALYSIS
    // ========================================================================

    void FeedPacket(uint64_t connectionId, std::span<const uint8_t> packet) {
        try {
            if (packet.empty()) return;

            // Early-exit if module is disabled (avoid work under lock)
            {
                std::shared_lock lock(m_mutex);
                if (!m_config.enabled) return;
            }

            // Detect protocol (lock-free, const method)
            P2PProtocol protocol = DetectProtocol(packet);
            if (protocol == P2PProtocol::UNKNOWN) return;

            // Data collected under lock, callbacks fired outside
            P2PConnection connSnapshot;
            bool maliciousDetected = false;
            bool shouldBlock = false;
            bool shouldAlert = false;
            uint32_t maliciousPid = 0;

            {
                std::unique_lock lock(m_mutex);

                // Enforce connection tracking bounds to prevent DoS
                if (m_connections.find(connectionId) == m_connections.end()) {
                    if (m_connections.size() >= MAX_TRACKED_CONNECTIONS) {
                        EvictOldestConnection();
                    }
                }

                // Update or create connection
                auto& conn = m_connections[connectionId];
                const bool isNewConnection = (conn.connectionId == 0);
                if (isNewConnection) {
                    conn.connectionId = connectionId;
                    conn.startTime = std::chrono::system_clock::now();
                }

                conn.protocol = protocol;
                conn.lastActivity = std::chrono::system_clock::now();
                conn.bytesReceived += packet.size();

                // Wire packet bytes into the global download counter.
                // Bandwidth-direction is not knowable at this layer (TrafficAnalyzer
                // only knows it received bytes from the wire), so account every
                // captured packet to bytesDownloaded — the upload counter is
                // updated by the policy/throttle path when send-side data is seen.
                m_stats.bytesDownloaded.fetch_add(packet.size(),
                    std::memory_order_relaxed);

                // If this connection belongs to a blocked process, mark and skip
                if (conn.processId != 0 && m_blockedProcesses.count(conn.processId) > 0) {
                    m_stats.connectionsBlocked++;
                    // Still track but don't fire detection callbacks
                    return;
                }

                // Extract BitTorrent infohash if applicable
                if (protocol == P2PProtocol::BITTORRENT_TCP && packet.size() >= 68) {
                    InfoHash ih;
                    std::copy_n(packet.begin() + 28, 20, ih.hash.begin());
                    ih.hexString = InfoHashToHex(ih.hash);
                    conn.infoHash = ih;

                    // Extract peer ID if present (bytes 48-67)
                    std::string peerIdStr(reinterpret_cast<const char*>(packet.data() + 48), 20);
                    conn.application = IdentifyClient(peerIdStr);
                    conn.applicationVersion = ExtractClientVersion(peerIdStr);

                    // Track swarm (caller holds m_mutex)
                    TrackSwarm(ih, connectionId);

                    // Check local malicious hash database
                    if (IsKnownMaliciousLocked(ih)) {
                        conn.isMalicious = true;
                        conn.threats.push_back(P2PThreatType::MALWARE_DISTRIBUTION);
                        maliciousDetected = true;
                        maliciousPid = conn.processId;
                        shouldBlock = m_config.blockMalicious;
                        shouldAlert = m_config.alertOnMalicious;
                    }
                }

                // Update statistics — count *new* P2P connections only.
                // The prior code incremented this every single packet, so a
                // single long-lived torrent could inflate the metric into the
                // millions and mask real fan-out detections downstream.
                if (isNewConnection) {
                    m_stats.p2pConnectionsDetected++;
                }
                UpdateProtocolStats(protocol);

                // Update per-application statistics
                switch (conn.application) {
                    case P2PApplication::QBITTORRENT:
                        m_stats.qbittorrentDetected++;
                        break;
                    case P2PApplication::UTORRENT:
                        m_stats.utorrentDetected++;
                        break;
                    case P2PApplication::TRANSMISSION:
                        m_stats.transmissionDetected++;
                        break;
                    case P2PApplication::UNKNOWN:
                        break;  // Don't count unknown
                    default:
                        m_stats.otherClientsDetected++;
                        break;
                }

                // Snapshot for callback (under lock so copy is consistent)
                connSnapshot = conn;
            }
            // Lock released -- safe to fire callbacks and perform blocking

            if (maliciousDetected) {
                SS_LOG_FATAL(L"Network", L"Malicious P2P detected: pid=%u, protocol=%d, infohash=%hs",
                    connSnapshot.processId,
                    static_cast<int>(connSnapshot.protocol),
                    connSnapshot.infoHash ? connSnapshot.infoHash->hexString.c_str() : "N/A");

                if (shouldBlock && maliciousPid != 0) {
                    BlockProcess(maliciousPid);
                }

                if (shouldAlert) {
                    GenerateAlert(connSnapshot, P2PThreatType::MALWARE_DISTRIBUTION);
                }
            }

            // Notify detection callbacks outside the lock
            NotifyDetection(connSnapshot);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FeedPacket - Exception: %hs", e.what());
        }
    }

    [[nodiscard]] std::pair<uint64_t, uint64_t> GetBandwidthUsage() const noexcept {
        uint64_t download = m_stats.bytesDownloaded.load();
        uint64_t upload = m_stats.bytesUploaded.load();
        return {download, upload};
    }

    // ========================================================================
    // POLICY ENFORCEMENT
    // ========================================================================

    bool BlockProcess(uint32_t pid) {
        std::unique_lock lock(m_mutex);

        try {
            m_blockedProcesses.insert(pid);

            // Block all existing connections
            for (auto& [connId, conn] : m_connections) {
                if (conn.processId == pid) {
                    conn.isMalicious = true;
                    conn.threats.push_back(P2PThreatType::POLICY_VIOLATION);
                    SS_LOG_INFO(L"Network", L"Blocked P2P connection: pid=%u, protocol=%d",
                        pid, static_cast<int>(conn.protocol));
                }
            }

            m_stats.connectionsBlocked++;
            SS_LOG_INFO(L"Network", L"Blocked P2P for process: %u", pid);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"BlockProcess - Exception: %hs", e.what());
            return false;
        }
    }

    bool UnblockProcess(uint32_t pid) {
        std::unique_lock lock(m_mutex);

        try {
            m_blockedProcesses.erase(pid);
            SS_LOG_INFO(L"Network", L"Unblocked P2P for process: %u", pid);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"UnblockProcess - Exception: %hs", e.what());
            return false;
        }
    }

    bool ThrottleProcess(uint32_t pid, uint64_t limitBps) {
        std::unique_lock lock(m_mutex);

        try {
            m_throttledProcesses[pid] = limitBps;

            SS_LOG_INFO(L"Network", L"Throttled P2P for process %u to %llu bytes/sec",
                pid, static_cast<unsigned long long>(limitBps));

            m_stats.connectionsThrottled++;

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"ThrottleProcess - Exception: %hs", e.what());
            return false;
        }
    }

    void SetPolicy(P2PPolicy policy) {
        std::unique_lock lock(m_mutex);
        m_config.policy = policy;
        SS_LOG_INFO(L"Network", L"P2P policy changed to: %d", static_cast<int>(policy));
    }

    [[nodiscard]] P2PPolicy GetPolicy() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.policy;
    }

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterDetectionCallback(P2PDetectionCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_detectionCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterAlertCallback(P2PAlertCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterSwarmCallback(SwarmCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_swarmCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterTorrentCallback(TorrentCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_torrentCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterDHTCallback(DHTCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_dhtCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);

        bool removed = false;
        removed |= (m_detectionCallbacks.erase(callbackId) > 0);
        removed |= (m_alertCallbacks.erase(callbackId) > 0);
        removed |= (m_swarmCallbacks.erase(callbackId) > 0);
        removed |= (m_torrentCallbacks.erase(callbackId) > 0);
        removed |= (m_dhtCallbacks.erase(callbackId) > 0);

        return removed;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const P2PMonitorStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const {
        std::shared_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"Network", L"=== P2PMonitor Diagnostics ===");
            SS_LOG_INFO(L"Network", L"Initialized: %d", static_cast<int>(m_initialized));
            SS_LOG_INFO(L"Network", L"Running: %d", static_cast<int>(m_running.load()));
            SS_LOG_INFO(L"Network", L"Active connections: %llu", static_cast<unsigned long long>(m_connections.size()));
            SS_LOG_INFO(L"Network", L"Active swarms: %llu", static_cast<unsigned long long>(m_swarms.size()));
            SS_LOG_INFO(L"Network", L"Tracked peers: %llu", static_cast<unsigned long long>(m_peers.size()));
            SS_LOG_INFO(L"Network", L"DHT nodes: %llu", static_cast<unsigned long long>(m_dhtNodes.size()));
            SS_LOG_INFO(L"Network", L"Malicious hashes: %llu", static_cast<unsigned long long>(m_maliciousHashes.size()));
            SS_LOG_INFO(L"Network", L"Blocked processes: %llu", static_cast<unsigned long long>(m_blockedProcesses.size()));
            SS_LOG_INFO(L"Network", L"Throttled processes: %llu", static_cast<unsigned long long>(m_throttledProcesses.size()));
            SS_LOG_INFO(L"Network", L"Total P2P detected: %llu", static_cast<unsigned long long>(m_stats.p2pConnectionsDetected.load()));
            SS_LOG_INFO(L"Network", L"BitTorrent connections: %llu", static_cast<unsigned long long>(m_stats.bittorrentConnections.load()));
            SS_LOG_INFO(L"Network", L"Malicious torrents: %llu", static_cast<unsigned long long>(m_stats.maliciousTorrents.load()));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"PerformDiagnostics - Exception: %hs", e.what());
            return false;
        }
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        std::shared_lock lock(m_mutex);

        try {
            // Validate output path
            if (outputPath.empty()) {
                SS_LOG_ERROR(L"Network", L"ExportDiagnostics - empty output path");
                return false;
            }

            HANDLE hFile = ::CreateFileW(
                outputPath.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (hFile == INVALID_HANDLE_VALUE) {
                SS_LOG_LAST_ERROR(L"Network", L"ExportDiagnostics - CreateFileW failed for %ls", outputPath.c_str());
                return false;
            }

            // RAII file handle
            struct HandleCloser {
                HANDLE h;
                ~HandleCloser() { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
            } handleGuard{ hFile };

            auto writeLine = [&](const std::string& line) -> bool {
                DWORD written = 0;
                return ::WriteFile(hFile, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr) != FALSE;
            };

            bool writeOk = true;
            writeOk = writeOk && writeLine("=== P2PMonitor Diagnostics ===\r\n");
            writeOk = writeOk && writeLine("Initialized: " + std::to_string(static_cast<int>(m_initialized)) + "\r\n");
            writeOk = writeOk && writeLine("Running: " + std::to_string(static_cast<int>(m_running.load())) + "\r\n");
            writeOk = writeOk && writeLine("Active connections: " + std::to_string(m_connections.size()) + "\r\n");
            writeOk = writeOk && writeLine("Active swarms: " + std::to_string(m_swarms.size()) + "\r\n");
            writeOk = writeOk && writeLine("Tracked peers: " + std::to_string(m_peers.size()) + "\r\n");
            writeOk = writeOk && writeLine("DHT nodes: " + std::to_string(m_dhtNodes.size()) + "\r\n");
            writeOk = writeOk && writeLine("Malicious hashes: " + std::to_string(m_maliciousHashes.size()) + "\r\n");
            writeOk = writeOk && writeLine("Blocked processes: " + std::to_string(m_blockedProcesses.size()) + "\r\n");
            writeOk = writeOk && writeLine("Throttled processes: " + std::to_string(m_throttledProcesses.size()) + "\r\n");
            writeOk = writeOk && writeLine("Total P2P detected: " + std::to_string(m_stats.p2pConnectionsDetected.load()) + "\r\n");
            writeOk = writeOk && writeLine("BitTorrent connections: " + std::to_string(m_stats.bittorrentConnections.load()) + "\r\n");
            writeOk = writeOk && writeLine("DHT queries: " + std::to_string(m_stats.dhtQueries.load()) + "\r\n");
            writeOk = writeOk && writeLine("eMule connections: " + std::to_string(m_stats.emuleConnections.load()) + "\r\n");
            writeOk = writeOk && writeLine("Malicious torrents: " + std::to_string(m_stats.maliciousTorrents.load()) + "\r\n");
            writeOk = writeOk && writeLine("Connections blocked: " + std::to_string(m_stats.connectionsBlocked.load()) + "\r\n");
            writeOk = writeOk && writeLine("Alerts generated: " + std::to_string(m_stats.alertsGenerated.load()) + "\r\n");
            writeOk = writeOk && writeLine("Policy: " + std::to_string(static_cast<int>(m_config.policy)) + "\r\n");

            if (!writeOk) {
                SS_LOG_ERROR(L"Network", L"ExportDiagnostics - write failed for %ls", outputPath.c_str());
                return false;
            }

            SS_LOG_INFO(L"Network", L"Exported P2PMonitor diagnostics to: %ls", outputPath.c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"ExportDiagnostics - Exception: %hs", e.what());
            return false;
        }
    }

    void SetThreatIntelStore(ThreatIntel::ThreatIntelStore* store) noexcept {
        std::unique_lock lock(m_mutex);
        m_threatIntel = store;
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    void MonitoringLoop() {
        SS_LOG_INFO(L"Network", L"P2PMonitor: Monitoring thread started");

        try {
            // Acquire ordering pairs with the release performed in Stop()
            // when m_running is set to false, ensuring the loop observes the
            // shutdown signal promptly without missing any prior writes.
            while (m_running.load(std::memory_order_acquire)) {
                // Sleep in short increments to allow responsive shutdown
                for (int i = 0; i < 50 && m_running.load(std::memory_order_acquire); ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                if (!m_running.load(std::memory_order_acquire)) break;

                // Cleanup stale connections
                CleanupStaleConnections();

                // Cleanup stale swarms
                CleanupStaleSwarms();

                // Update statistics
                UpdateStatistics();
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"P2PMonitor monitoring loop exception: %hs", e.what());
        }

        SS_LOG_INFO(L"Network", L"P2PMonitor: Monitoring thread stopped");
    }

    void CleanupStaleConnections() {
        std::unique_lock lock(m_mutex);

        try {
            auto now = std::chrono::system_clock::now();
            std::vector<uint64_t> toRemove;

            for (const auto& [connId, conn] : m_connections) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - conn.lastActivity);
                if (age.count() > CONNECTION_TIMEOUT_SEC) {
                    toRemove.push_back(connId);
                }
            }

            for (uint64_t id : toRemove) {
                m_connections.erase(id);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"CleanupStaleConnections - Exception: %hs", e.what());
        }
    }

    void CleanupStaleSwarms() {
        std::unique_lock lock(m_mutex);

        try {
            auto now = std::chrono::system_clock::now();
            std::vector<InfoHash> toRemove;

            for (const auto& [hash, swarm] : m_swarms) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - swarm.lastActivity);
                if (age.count() > SWARM_TIMEOUT_SEC) {
                    toRemove.push_back(hash);
                }
            }

            for (const auto& hash : toRemove) {
                m_swarmConnections.erase(hash);
                m_swarms.erase(hash);
            }

            m_stats.activeSwarms = static_cast<uint32_t>(m_swarms.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"CleanupStaleSwarms - Exception: %hs", e.what());
        }
    }

    void UpdateStatistics() {
        std::shared_lock lock(m_mutex);

        try {
            m_stats.activeSwarms = static_cast<uint32_t>(m_swarms.size());
            m_stats.uniqueInfoHashes = static_cast<uint64_t>(m_swarms.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"UpdateStatistics - Exception: %hs", e.what());
        }
    }

    void TrackSwarm(const InfoHash& infoHash, uint64_t connectionId) {
        // NOTE: Caller must hold m_mutex.
        try {
            auto& swarm = m_swarms[infoHash];
            if (swarm.infoHash.hexString.empty()) {
                swarm.infoHash = infoHash;
                swarm.firstSeen = std::chrono::system_clock::now();
            }

            swarm.lastActivity = std::chrono::system_clock::now();

            // Deduplicate: only increment connectedPeers for new connections
            // Use a set of connection IDs tracked per swarm in our tracking map
            auto& connSet = m_swarmConnections[infoHash];
            if (connSet.insert(connectionId).second) {
                swarm.connectedPeers++;
            }

            // Check size limit
            if (m_swarms.size() > P2PMonitorConstants::MAX_TRACKED_SWARMS) {
                EvictOldestSwarm();
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"TrackSwarm - Exception: %hs", e.what());
        }
    }

    void EvictOldestSwarm() {
        auto oldest = m_swarms.begin();
        for (auto it = m_swarms.begin(); it != m_swarms.end(); ++it) {
            if (it->second.lastActivity < oldest->second.lastActivity) {
                oldest = it;
            }
        }
        if (oldest != m_swarms.end()) {
            m_swarmConnections.erase(oldest->first);
            m_swarms.erase(oldest);
        }
    }

    void EvictOldestConnection() {
        if (m_connections.empty()) return;
        auto oldest = m_connections.begin();
        for (auto it = m_connections.begin(); it != m_connections.end(); ++it) {
            if (it->second.lastActivity < oldest->second.lastActivity) {
                oldest = it;
            }
        }
        if (oldest != m_connections.end()) {
            // Remove the connection's id from any per-swarm tracking set, otherwise
            // m_swarmConnections retains stale ids forever and inflates the
            // observed connectedPeers count for that swarm.
            const uint64_t evictedId = oldest->first;
            for (auto& [hash, idSet] : m_swarmConnections) {
                idSet.erase(evictedId);
            }
            m_connections.erase(oldest);
        }
    }

    void UpdateProtocolStats(P2PProtocol protocol) {
        switch (protocol) {
            case P2PProtocol::BITTORRENT_TCP:
            case P2PProtocol::BITTORRENT_UDP:
                m_stats.bittorrentConnections++;
                break;
            case P2PProtocol::DHT:
                m_stats.dhtQueries++;
                break;
            case P2PProtocol::EMULE_TCP:
            case P2PProtocol::EMULE_UDP:
            case P2PProtocol::KADEMLIA:
                m_stats.emuleConnections++;
                break;
            default:
                m_stats.otherP2PConnections++;
                break;
        }
    }

    void GenerateAlert(const P2PConnection& conn, P2PThreatType threatType) {
        try {
            P2PAlert alert;
            alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed) + 1;
            alert.timestamp = std::chrono::system_clock::now();
            alert.protocol = conn.protocol;
            alert.application = conn.application;
            alert.threatType = threatType;
            alert.processId = conn.processId;
            alert.processName = conn.processName;
            alert.processPath = conn.processPath;
            alert.infoHash = conn.infoHash;
            alert.remoteIP = conn.remoteIP;
            alert.remotePort = conn.remotePort;
            alert.bytesTransferred = conn.bytesSent + conn.bytesReceived;

            {
                std::shared_lock lock(m_mutex);
                alert.appliedPolicy = m_config.policy;
            }

            m_stats.alertsGenerated++;

            NotifyAlert(alert);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GenerateAlert - Exception: %hs", e.what());
        }
    }

    void NotifyDetection(const P2PConnection& conn) {
        // Copy callbacks under lock, invoke outside
        std::vector<P2PDetectionCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_detectionCallbacks.size());
            for (const auto& [id, cb] : m_detectionCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }
        try {
            for (const auto& callback : callbacks) {
                callback(conn);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"NotifyDetection - callback exception: %hs", e.what());
        }
    }

    void NotifyAlert(const P2PAlert& alert) {
        std::vector<P2PAlertCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_alertCallbacks.size());
            for (const auto& [id, cb] : m_alertCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }
        try {
            for (const auto& callback : callbacks) {
                callback(alert);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"NotifyAlert - callback exception: %hs", e.what());
        }
    }

    void NotifySwarm(const SwarmInfo& swarm) {
        std::vector<SwarmCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_swarmCallbacks.size());
            for (const auto& [id, cb] : m_swarmCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }
        try {
            for (const auto& callback : callbacks) {
                callback(swarm);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"NotifySwarm - callback exception: %hs", e.what());
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    std::atomic<bool> m_running{ false };

    P2PMonitorConfig m_config;
    P2PMonitorStatistics m_stats;

    // Tracking
    std::unordered_map<uint64_t, P2PConnection> m_connections;
    std::unordered_map<InfoHash, SwarmInfo, InfoHash::Hash> m_swarms;
    std::unordered_map<InfoHash, std::unordered_set<uint64_t>, InfoHash::Hash> m_swarmConnections;  // Per-swarm connection dedup
    std::unordered_map<std::string, PeerInfo> m_peers;
    std::unordered_map<uint32_t, DHTInfo> m_dhtNodes;
    std::unordered_map<InfoHash, std::string, InfoHash::Hash> m_maliciousHashes;

    // Policy enforcement
    std::unordered_set<uint32_t> m_blockedProcesses;
    std::unordered_map<uint32_t, uint64_t> m_throttledProcesses;  // pid -> bps limit

    /// @brief Infrastructure integrations (non-owning, orchestrator manages lifetime)
    ThreatIntel::ThreatIntelStore* m_threatIntel{nullptr};

    // Callbacks
    std::unordered_map<uint64_t, P2PDetectionCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, P2PAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, SwarmCallback> m_swarmCallbacks;
    std::unordered_map<uint64_t, TorrentCallback> m_torrentCallbacks;
    std::unordered_map<uint64_t, DHTCallback> m_dhtCallbacks;
    uint64_t m_nextCallbackId{ 0 };
    std::atomic<uint64_t> m_nextAlertId{ 0 };

    // Threading
    std::thread m_monitorThread;
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

P2PMonitor& P2PMonitor::Instance() {
    static P2PMonitor instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

P2PMonitor::P2PMonitor()
    : m_impl(std::make_unique<P2PMonitorImpl>()) {
    SS_LOG_INFO(L"Network", L"P2PMonitor instance created");
}

P2PMonitor::~P2PMonitor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"Network", L"P2PMonitor instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool P2PMonitor::Initialize(const P2PMonitorConfig& config) {
    return m_impl->Initialize(config);
}

bool P2PMonitor::Start() {
    return m_impl->Start();
}

void P2PMonitor::Stop() {
    m_impl->Stop();
}

void P2PMonitor::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool P2PMonitor::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

bool P2PMonitor::IsP2PTraffic(uint32_t pid) {
    return m_impl->IsP2PTraffic(pid);
}

std::vector<P2PConnection> P2PMonitor::GetP2PConnections(uint32_t pid) const {
    return m_impl->GetP2PConnections(pid);
}

std::vector<P2PConnection> P2PMonitor::GetAllP2PConnections() const {
    return m_impl->GetAllP2PConnections();
}

P2PProtocol P2PMonitor::DetectProtocol(std::span<const uint8_t> packet) const {
    return m_impl->DetectProtocol(packet);
}

std::vector<SwarmInfo> P2PMonitor::GetActiveSwarms() const {
    return m_impl->GetActiveSwarms();
}

std::optional<SwarmInfo> P2PMonitor::GetSwarm(const InfoHash& infoHash) const {
    return m_impl->GetSwarm(infoHash);
}

std::optional<SwarmInfo> P2PMonitor::GetSwarm(const std::string& infoHashHex) const {
    return m_impl->GetSwarm(infoHashHex);
}

std::optional<TorrentInfo> P2PMonitor::LookupTorrent(const InfoHash& infoHash) const {
    return m_impl->LookupTorrent(infoHash);
}

bool P2PMonitor::IsKnownMalicious(const InfoHash& infoHash) const {
    return m_impl->IsKnownMalicious(infoHash);
}

void P2PMonitor::AddMaliciousHash(const InfoHash& infoHash, const std::string& reason) {
    m_impl->AddMaliciousHash(infoHash, reason);
}

std::optional<DHTInfo> P2PMonitor::GetDHTInfo(uint32_t pid) const {
    return m_impl->GetDHTInfo(pid);
}

void P2PMonitor::FeedPacket(uint64_t connectionId, std::span<const uint8_t> packet) {
    m_impl->FeedPacket(connectionId, packet);
}

std::pair<uint64_t, uint64_t> P2PMonitor::GetBandwidthUsage() const noexcept {
    return m_impl->GetBandwidthUsage();
}

bool P2PMonitor::BlockProcess(uint32_t pid) {
    return m_impl->BlockProcess(pid);
}

bool P2PMonitor::UnblockProcess(uint32_t pid) {
    return m_impl->UnblockProcess(pid);
}

bool P2PMonitor::ThrottleProcess(uint32_t pid, uint64_t limitBps) {
    return m_impl->ThrottleProcess(pid, limitBps);
}

void P2PMonitor::SetPolicy(P2PPolicy policy) {
    m_impl->SetPolicy(policy);
}

P2PPolicy P2PMonitor::GetPolicy() const noexcept {
    return m_impl->GetPolicy();
}

uint64_t P2PMonitor::RegisterDetectionCallback(P2PDetectionCallback callback) {
    return m_impl->RegisterDetectionCallback(std::move(callback));
}

uint64_t P2PMonitor::RegisterAlertCallback(P2PAlertCallback callback) {
    return m_impl->RegisterAlertCallback(std::move(callback));
}

uint64_t P2PMonitor::RegisterSwarmCallback(SwarmCallback callback) {
    return m_impl->RegisterSwarmCallback(std::move(callback));
}

uint64_t P2PMonitor::RegisterTorrentCallback(TorrentCallback callback) {
    return m_impl->RegisterTorrentCallback(std::move(callback));
}

uint64_t P2PMonitor::RegisterDHTCallback(DHTCallback callback) {
    return m_impl->RegisterDHTCallback(std::move(callback));
}

bool P2PMonitor::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

const P2PMonitorStatistics& P2PMonitor::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void P2PMonitor::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

bool P2PMonitor::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool P2PMonitor::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

// ============================================================================
// Store Wiring (Orchestrator-Injected Dependencies)
// ============================================================================

void P2PMonitor::SetThreatIntelStore(ThreatIntel::ThreatIntelStore* store) noexcept {
    if (!m_impl) return;
    m_impl->SetThreatIntelStore(store);
    SS_LOG_INFO(L"Network", L"P2PMonitor: ThreatIntelStore %ls",
                store ? L"wired" : L"cleared");
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
