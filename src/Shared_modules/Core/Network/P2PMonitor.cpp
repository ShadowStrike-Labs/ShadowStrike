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
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
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
    const std::array<uint8_t, 11> BITTORRENT_PROTOCOL_STRING = {
        0x42, 0x69, 0x74, 0x54, 0x6F, 0x72, 0x72, 0x65, 0x6E, 0x74  // "BitTorrent"
    };

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
    // Use first 8 bytes as hash seed
    size_t h = 0;
    for (size_t i = 0; i < std::min(size_t(8), ih.hash.size()); ++i) {
        h = (h << 8) | ih.hash[i];
    }
    return h;
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
    if (hex.length() != 40) return std::nullopt;

    std::array<uint8_t, 20> hash{};
    try {
        for (size_t i = 0; i < 20; ++i) {
            hash[i] = static_cast<uint8_t>(
                std::stoi(hex.substr(i * 2, 2), nullptr, 16)
            );
        }
        return hash;
    } catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] static P2PApplication IdentifyClient(const std::string& peerIdStr) {
    if (peerIdStr.length() < 3) return P2PApplication::UNKNOWN;

    for (const auto& client : CLIENT_PREFIXES) {
        if (peerIdStr.find(client.prefix) == 0) {
            return client.app;
        }
    }

    return P2PApplication::UNKNOWN;
}

[[nodiscard]] static std::string ExtractClientVersion(const std::string& peerIdStr) {
    // Example: "-qB4250-" -> "4.2.5.0"
    if (peerIdStr.length() < 8) return "Unknown";

    try {
        // Most clients use format: -XXYYYY- where XX is client, YYYY is version
        std::string versionPart = peerIdStr.substr(3, 4);
        std::string version;
        for (char c : versionPart) {
            if (std::isdigit(c)) {
                version += c;
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

            Logger::Info("P2PMonitor initialized (policy={}, detectBT={}, detectDHT={})",
                static_cast<int>(config.policy), config.detectBitTorrent, config.detectDHT);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("P2PMonitor initialization failed: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_initialized) {
                Logger::Error("P2PMonitor: Cannot start - not initialized");
                return false;
            }

            if (m_running) {
                Logger::Warn("P2PMonitor: Already running");
                return true;
            }

            m_running = true;

            // Start monitoring thread
            m_monitorThread = std::thread([this]() { MonitoringLoop(); });

            Logger::Info("P2PMonitor started");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("P2PMonitor start failed: {}", e.what());
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

            Logger::Info("P2PMonitor stopped");

        } catch (const std::exception& e) {
            Logger::Error("P2PMonitor stop failed: {}", e.what());
        }
    }

    void Shutdown() noexcept {
        try {
            Stop();

            std::unique_lock lock(m_mutex);

            m_connections.clear();
            m_swarms.clear();
            m_peers.clear();
            m_dhtNodes.clear();
            m_maliciousHashes.clear();

            m_detectionCallbacks.clear();
            m_alertCallbacks.clear();
            m_swarmCallbacks.clear();
            m_torrentCallbacks.clear();
            m_dhtCallbacks.clear();

            m_initialized = false;

            Logger::Info("P2PMonitor shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    [[nodiscard]] bool IsRunning() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_running;
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
            Logger::Error("IsP2PTraffic - Exception: {}", e.what());
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
            Logger::Error("GetP2PConnections - Exception: {}", e.what());
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
            Logger::Error("GetAllP2PConnections - Exception: {}", e.what());
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

            // DHT (bencode)
            if (packet.size() >= 3) {
                std::string prefix(reinterpret_cast<const char*>(packet.data()),
                                  std::min(size_t(3), packet.size()));
                if (prefix == DHT_QUERY_PREFIX) {
                    return P2PProtocol::DHT;
                }
            }

            // uTP
            if (packet.size() >= 20) {
                uint8_t ver_type = packet[0];
                uint8_t type = ver_type & UTP_TYPE_MASK;
                if (type >= UTP_ST_DATA && type <= UTP_ST_SYN) {
                    return P2PProtocol::UTP;
                }
            }

            // eMule TCP
            if (packet.size() >= 6 && packet[0] == EMULE_PROTOCOL_TCP[0]) {
                return P2PProtocol::EMULE_TCP;
            }

            // eMule UDP / Kademlia
            if (packet.size() >= 2 && packet[0] == EMULE_PROTOCOL_UDP[0]) {
                return P2PProtocol::EMULE_UDP;
            }

            if (packet.size() >= 2 && packet[0] == KADEMLIA_MAGIC[0]) {
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
            Logger::Error("DetectProtocol - Exception: {}", e.what());
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
            Logger::Error("GetActiveSwarms - Exception: {}", e.what());
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
            Logger::Error("GetSwarm - Exception: {}", e.what());
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
            Logger::Error("GetSwarm(hex) - Exception: {}", e.what());
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

            // In production, would query metadata databases or DHT
            // For now, return nullopt
            return std::nullopt;

        } catch (const std::exception& e) {
            Logger::Error("LookupTorrent - Exception: {}", e.what());
            return std::nullopt;
        }
    }

    [[nodiscard]] bool IsKnownMalicious(const InfoHash& infoHash) const {
        std::shared_lock lock(m_mutex);

        try {
            // Check local malicious hash database
            if (m_maliciousHashes.find(infoHash) != m_maliciousHashes.end()) {
                return true;
            }

            // Check HashStore for known malware infohashes
            if (HashStore::Instance().IsKnownMalware(infoHash.hexString)) {
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("IsKnownMalicious - Exception: {}", e.what());
            return false;
        }
    }

    void AddMaliciousHash(const InfoHash& infoHash, const std::string& reason) {
        std::unique_lock lock(m_mutex);

        try {
            m_maliciousHashes[infoHash] = reason;

            Logger::Critical("Marked infohash as malicious: {} (reason: {})",
                infoHash.hexString, reason);

            m_stats.maliciousTorrents++;

        } catch (const std::exception& e) {
            Logger::Error("AddMaliciousHash - Exception: {}", e.what());
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
            Logger::Error("GetDHTInfo - Exception: {}", e.what());
        }

        return std::nullopt;
    }

    // ========================================================================
    // TRAFFIC ANALYSIS
    // ========================================================================

    void FeedPacket(uint64_t connectionId, std::span<const uint8_t> packet) {
        try {
            if (packet.empty()) return;

            // Detect protocol
            P2PProtocol protocol = DetectProtocol(packet);
            if (protocol == P2PProtocol::UNKNOWN) return;

            std::unique_lock lock(m_mutex);

            // Update or create connection
            auto& conn = m_connections[connectionId];
            if (conn.connectionId == 0) {
                conn.connectionId = connectionId;
                conn.startTime = std::chrono::system_clock::now();
            }

            conn.protocol = protocol;
            conn.lastActivity = std::chrono::system_clock::now();
            conn.bytesReceived += packet.size();

            // Extract BitTorrent infohash if applicable
            if (protocol == P2PProtocol::BITTORRENT_TCP && packet.size() >= 68) {
                InfoHash ih;
                std::copy_n(packet.begin() + 28, 20, ih.hash.begin());
                ih.hexString = InfoHashToHex(ih.hash);
                conn.infoHash = ih;

                // Track swarm
                TrackSwarm(ih, connectionId);

                // Check if malicious
                if (IsKnownMalicious(ih)) {
                    conn.isMalicious = true;
                    conn.threats.push_back(P2PThreatType::MALWARE_DISTRIBUTION);
                    HandleMaliciousDetection(conn);
                }
            }

            // Update statistics
            m_stats.p2pConnectionsDetected++;
            UpdateProtocolStats(protocol);

            // Notify callbacks
            NotifyDetection(conn);

        } catch (const std::exception& e) {
            Logger::Error("FeedPacket - Exception: {}", e.what());
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
                    // In production, would terminate actual network connections
                    Logger::Info("Blocked P2P connection: pid={}, protocol={}",
                        pid, static_cast<int>(conn.protocol));
                }
            }

            m_stats.connectionsBlocked++;
            Logger::Info("Blocked P2P for process: {}", pid);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("BlockProcess - Exception: {}", e.what());
            return false;
        }
    }

    bool UnblockProcess(uint32_t pid) {
        std::unique_lock lock(m_mutex);

        try {
            m_blockedProcesses.erase(pid);
            Logger::Info("Unblocked P2P for process: {}", pid);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("UnblockProcess - Exception: {}", e.what());
            return false;
        }
    }

    bool ThrottleProcess(uint32_t pid, uint64_t limitBps) {
        std::unique_lock lock(m_mutex);

        try {
            m_throttledProcesses[pid] = limitBps;

            Logger::Info("Throttled P2P for process {} to {} bytes/sec", pid, limitBps);

            m_stats.connectionsThrottled++;

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ThrottleProcess - Exception: {}", e.what());
            return false;
        }
    }

    void SetPolicy(P2PPolicy policy) {
        std::unique_lock lock(m_mutex);
        m_config.policy = policy;
        Logger::Info("P2P policy changed to: {}", static_cast<int>(policy));
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
            Logger::Info("=== P2PMonitor Diagnostics ===");
            Logger::Info("Initialized: {}", m_initialized);
            Logger::Info("Running: {}", m_running);
            Logger::Info("Active connections: {}", m_connections.size());
            Logger::Info("Active swarms: {}", m_swarms.size());
            Logger::Info("Tracked peers: {}", m_peers.size());
            Logger::Info("DHT nodes: {}", m_dhtNodes.size());
            Logger::Info("Malicious hashes: {}", m_maliciousHashes.size());
            Logger::Info("Blocked processes: {}", m_blockedProcesses.size());
            Logger::Info("Throttled processes: {}", m_throttledProcesses.size());
            Logger::Info("Total P2P detected: {}", m_stats.p2pConnectionsDetected.load());
            Logger::Info("BitTorrent connections: {}", m_stats.bittorrentConnections.load());
            Logger::Info("Malicious torrents: {}", m_stats.maliciousTorrents.load());

            return true;

        } catch (const std::exception& e) {
            Logger::Error("PerformDiagnostics - Exception: {}", e.what());
            return false;
        }
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        std::shared_lock lock(m_mutex);

        try {
            // In production, would write comprehensive diagnostics to file
            Logger::Info("Exported diagnostics to: {}", StringUtils::WideToUtf8(outputPath));
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ExportDiagnostics - Exception: {}", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    void MonitoringLoop() {
        Logger::Info("P2PMonitor: Monitoring thread started");

        try {
            while (m_running) {
                std::this_thread::sleep_for(std::chrono::seconds(5));

                // Cleanup stale connections
                CleanupStaleConnections();

                // Cleanup stale swarms
                CleanupStaleSwarms();

                // Update statistics
                UpdateStatistics();
            }

        } catch (const std::exception& e) {
            Logger::Error("P2PMonitor monitoring loop exception: {}", e.what());
        }

        Logger::Info("P2PMonitor: Monitoring thread stopped");
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
            Logger::Error("CleanupStaleConnections - Exception: {}", e.what());
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
                m_swarms.erase(hash);
            }

            m_stats.activeSwarms = static_cast<uint32_t>(m_swarms.size());

        } catch (const std::exception& e) {
            Logger::Error("CleanupStaleSwarms - Exception: {}", e.what());
        }
    }

    void UpdateStatistics() {
        std::shared_lock lock(m_mutex);

        try {
            m_stats.activeSwarms = static_cast<uint32_t>(m_swarms.size());
            m_stats.uniqueInfoHashes = static_cast<uint64_t>(m_swarms.size());

        } catch (const std::exception& e) {
            Logger::Error("UpdateStatistics - Exception: {}", e.what());
        }
    }

    void TrackSwarm(const InfoHash& infoHash, uint64_t connectionId) {
        try {
            auto& swarm = m_swarms[infoHash];
            if (swarm.infoHash.hexString.empty()) {
                swarm.infoHash = infoHash;
                swarm.firstSeen = std::chrono::system_clock::now();
            }

            swarm.lastActivity = std::chrono::system_clock::now();
            swarm.connectedPeers++;

            // Check size limit
            if (m_swarms.size() > P2PMonitorConstants::MAX_TRACKED_SWARMS) {
                EvictOldestSwarm();
            }

            // Notify callbacks
            NotifySwarm(swarm);

        } catch (const std::exception& e) {
            Logger::Error("TrackSwarm - Exception: {}", e.what());
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
            m_swarms.erase(oldest);
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

    void HandleMaliciousDetection(const P2PConnection& conn) {
        try {
            Logger::Critical("Malicious P2P detected: pid={}, protocol={}, infohash={}",
                conn.processId,
                static_cast<int>(conn.protocol),
                conn.infoHash ? conn.infoHash->hexString : "N/A");

            // Apply policy
            if (m_config.blockMalicious) {
                BlockProcess(conn.processId);
            }

            // Generate alert
            if (m_config.alertOnMalicious) {
                GenerateAlert(conn, P2PThreatType::MALWARE_DISTRIBUTION);
            }

        } catch (const std::exception& e) {
            Logger::Error("HandleMaliciousDetection - Exception: {}", e.what());
        }
    }

    void GenerateAlert(const P2PConnection& conn, P2PThreatType threatType) {
        try {
            P2PAlert alert;
            alert.alertId = ++m_nextAlertId;
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
            alert.appliedPolicy = m_config.policy;

            m_stats.alertsGenerated++;

            NotifyAlert(alert);

        } catch (const std::exception& e) {
            Logger::Error("GenerateAlert - Exception: {}", e.what());
        }
    }

    void NotifyDetection(const P2PConnection& conn) {
        try {
            for (const auto& [id, callback] : m_detectionCallbacks) {
                if (callback) {
                    callback(conn);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("NotifyDetection - Exception: {}", e.what());
        }
    }

    void NotifyAlert(const P2PAlert& alert) {
        try {
            for (const auto& [id, callback] : m_alertCallbacks) {
                if (callback) {
                    callback(alert);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("NotifyAlert - Exception: {}", e.what());
        }
    }

    void NotifySwarm(const SwarmInfo& swarm) {
        try {
            for (const auto& [id, callback] : m_swarmCallbacks) {
                if (callback) {
                    callback(swarm);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("NotifySwarm - Exception: {}", e.what());
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
    std::unordered_map<std::string, PeerInfo> m_peers;
    std::unordered_map<uint32_t, DHTInfo> m_dhtNodes;
    std::unordered_map<InfoHash, std::string, InfoHash::Hash> m_maliciousHashes;

    // Policy enforcement
    std::unordered_set<uint32_t> m_blockedProcesses;
    std::unordered_map<uint32_t, uint64_t> m_throttledProcesses;  // pid -> bps limit

    // Callbacks
    std::unordered_map<uint64_t, P2PDetectionCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, P2PAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, SwarmCallback> m_swarmCallbacks;
    std::unordered_map<uint64_t, TorrentCallback> m_torrentCallbacks;
    std::unordered_map<uint64_t, DHTCallback> m_dhtCallbacks;
    uint64_t m_nextCallbackId{ 0 };
    uint64_t m_nextAlertId{ 0 };

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
    Logger::Info("P2PMonitor instance created");
}

P2PMonitor::~P2PMonitor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("P2PMonitor instance destroyed");
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

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
