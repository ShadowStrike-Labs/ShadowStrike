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
 * ShadowStrike Core Network - P2P MONITOR (The Tracker)
 * ============================================================================
 *
 * @file P2PMonitor.hpp
 * @brief Enterprise-grade peer-to-peer traffic detection and control engine.
 *
 * This module provides comprehensive detection, monitoring, and control of
 * Peer-to-Peer (P2P) network traffic including BitTorrent, DHT overlays,
 * and other decentralized protocols used for both legitimate and malicious
 * purposes.
 *
 * Key Capabilities:
 * =================
 * 1. PROTOCOL DETECTION
 *    - BitTorrent protocol (BEP)
 *    - DHT (Distributed Hash Table)
 *    - uTP (Micro Transport Protocol)
 *    - Peer Exchange (PEX)
 *    - Tracker communications
 *
 * 2. TRAFFIC ANALYSIS
 *    - Bandwidth consumption tracking
 *    - Peer connection analysis
 *    - Swarm participation detection
 *    - Torrent metadata extraction
 *
 * 3. THREAT DETECTION
 *    - P2P botnet detection
 *    - Malicious torrent identification
 *    - Cryptominer distribution
 *    - Copyright infringement alerts
 *
 * 4. POLICY ENFORCEMENT
 *    - Bandwidth throttling
 *    - Connection limiting
 *    - Protocol blocking
 *    - Application control
 *
 * 5. COMPLIANCE MONITORING
 *    - Corporate policy enforcement
 *    - License compliance
 *    - Data exfiltration prevention
 *
 * P2P Monitoring Architecture:
 * ============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         P2PMonitor                                  │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ProtocolDetect│  │TrafficAnalyz │  │    ThreatCorrelator      │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - BitTorrent │  │ - Bandwidth  │  │ - Botnet Detection       │  │
 *   │  │ - DHT        │  │ - Peers      │  │ - Malware Distribution   │  │
 *   │  │ - uTP        │  │ - Metadata   │  │ - Data Exfiltration      │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │PolicyEnforce │  │ComplianceMon │  │    SwarmAnalyzer         │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Throttle   │  │ - Corporate  │  │ - Peer Count             │  │
 *   │  │ - Block      │  │ - Legal      │  │ - Hash Lookup            │  │
 *   │  │ - Limit      │  │ - License    │  │ - Content ID             │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * P2P Protocols Detected:
 * =======================
 * - BitTorrent (TCP/UDP)
 * - uTP (Micro Transport Protocol)
 * - DHT (Mainline/Kademlia)
 * - PEX (Peer Exchange)
 * - Tracker (HTTP/UDP)
 * - Magnet links
 * - WebTorrent
 * - eMule/eDonkey
 * - Gnutella
 * - Direct Connect (DC++)
 *
 * Applications Detected:
 * ======================
 * - qBittorrent, uTorrent, Transmission
 * - BitTorrent, Deluge, Vuze
 * - eMule, BitComet, Tixati
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1071: Application Layer Protocol
 * - T1090: Proxy (P2P overlay)
 * - T1105: Ingress Tool Transfer
 * - T1567: Exfiltration Over Web Service
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Concurrent traffic analysis supported
 * - Lock-free statistics updates
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see BotnetDetector.hpp for P2P botnet detection
 * @see NetworkMonitor.hpp for traffic monitoring
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // Network utilities
#include "../../Utils/ProcessUtils.hpp"       // Client process identification
#include "../../PatternStore/PatternStore.hpp" // Protocol patterns
#include "../../HashStore/HashStore.hpp"      // Torrent infohash lookups
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Malicious torrent IOCs
#include "../../Whitelist/WhiteListStore.hpp" // Allowed P2P applications

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class P2PMonitorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace P2PMonitorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // BitTorrent protocol
    constexpr uint8_t BITTORRENT_PROTOCOL_HEADER[] = { 0x13, 0x42, 0x69, 0x74, 0x54, 0x6F, 0x72, 0x72, 0x65, 0x6E, 0x74 };  // "\x13BitTorrent"
    constexpr size_t BITTORRENT_HEADER_SIZE = 68;
    constexpr size_t INFO_HASH_SIZE = 20;
    constexpr size_t PEER_ID_SIZE = 20;

    // DHT
    constexpr uint16_t DHT_DEFAULT_PORT = 6881;
    constexpr size_t DHT_NODE_ID_SIZE = 20;
    constexpr char DHT_MAGIC[] = "d1:";

    // Detection
    constexpr double CONFIDENCE_THRESHOLD = 0.70;
    constexpr uint32_t MIN_PEERS_FOR_SWARM = 3;
    constexpr uint32_t MIN_PACKETS_FOR_DETECTION = 5;

    // Tracking
    constexpr size_t MAX_TRACKED_SWARMS = 1000;
    constexpr size_t MAX_TRACKED_PEERS = 10000;
    constexpr size_t MAX_INFOHASH_CACHE = 100000;
    constexpr uint32_t PEER_TIMEOUT_SEC = 300;

    // Rate limiting
    constexpr uint64_t DEFAULT_BANDWIDTH_LIMIT_BPS = 0;           // No limit
    constexpr uint32_t DEFAULT_CONNECTION_LIMIT = 0;              // No limit

}  // namespace P2PMonitorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum P2PProtocol
 * @brief P2P protocol types.
 */
enum class P2PProtocol : uint8_t {
    UNKNOWN = 0,

    // BitTorrent family
    BITTORRENT_TCP = 1,
    BITTORRENT_UDP = 2,
    UTP = 3,                       // Micro Transport Protocol
    DHT = 4,                       // Distributed Hash Table
    PEX = 5,                       // Peer Exchange
    TRACKER_HTTP = 6,
    TRACKER_UDP = 7,
    WEBTORRENT = 8,
    MAGNET = 9,

    // eMule family
    EMULE_TCP = 20,
    EMULE_UDP = 21,
    KADEMLIA = 22,

    // Other protocols
    GNUTELLA = 30,
    DIRECT_CONNECT = 31,
    ARES = 32,
    FASTTRACK = 33,

    // IPFS
    IPFS = 40,
    LIBP2P = 41
};

/**
 * @enum P2PApplication
 * @brief Known P2P applications.
 */
enum class P2PApplication : uint16_t {
    UNKNOWN = 0,

    // BitTorrent clients
    QBITTORRENT = 100,
    UTORRENT = 101,
    TRANSMISSION = 102,
    BITTORRENT = 103,
    DELUGE = 104,
    VUZE = 105,
    BITCOMET = 106,
    TIXATI = 107,
    RTORRENT = 108,
    LIBTORRENT = 109,

    // eMule clients
    EMULE = 200,
    AMULE = 201,

    // Other
    GNUTELLA_CLIENT = 300,
    DCPP = 301,                    // DC++

    // Web-based
    WEBTORRENT_CLIENT = 400,
    POPCORN_TIME = 401,

    // IPFS
    IPFS_CLIENT = 500
};

/**
 * @enum TorrentCategory
 * @brief Category of torrent content.
 */
enum class TorrentCategory : uint8_t {
    UNKNOWN = 0,
    SOFTWARE = 1,
    VIDEO = 2,
    AUDIO = 3,
    DOCUMENTS = 4,
    GAMES = 5,
    ADULT = 6,
    OTHER = 7,
    MALWARE = 8,                   // Known malicious
    LEGITIMATE = 9                 // Known safe (Linux ISOs, etc.)
};

/**
 * @enum P2PThreatType
 * @brief Threat types in P2P context.
 */
enum class P2PThreatType : uint8_t {
    NONE = 0,
    MALWARE_DISTRIBUTION = 1,
    BOTNET_COMMUNICATION = 2,
    CRYPTOMINER = 3,
    DATA_EXFILTRATION = 4,
    COPYRIGHT_VIOLATION = 5,
    POLICY_VIOLATION = 6,
    BANDWIDTH_ABUSE = 7,
    UNKNOWN_PROTOCOL = 8
};

/**
 * @enum P2PPolicy
 * @brief Policy for P2P traffic.
 */
enum class P2PPolicy : uint8_t {
    ALLOW = 0,
    MONITOR = 1,
    THROTTLE = 2,                  // Limit bandwidth
    LIMIT_CONNECTIONS = 3,
    BLOCK_KNOWN_MALICIOUS = 4,
    BLOCK_ALL = 5,
    ALERT_ONLY = 6
};

/**
 * @enum DetectionConfidence
 * @brief Confidence of P2P detection.
 */
enum class P2PConfidence : uint8_t {
    NONE = 0,
    LOW = 1,                       // < 50%
    MEDIUM = 2,                    // 50-75%
    HIGH = 3,                      // 75-95%
    DEFINITE = 4                   // > 95%
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct InfoHash
 * @brief BitTorrent infohash.
 */
struct alignas(32) InfoHash {
    std::array<uint8_t, 20> hash{ 0 };
    std::string hexString;

    bool operator==(const InfoHash& other) const noexcept;

    struct Hash {
        size_t operator()(const InfoHash& ih) const noexcept;
    };
};

/**
 * @struct PeerInfo
 * @brief Information about a P2P peer.
 */
struct alignas(64) PeerInfo {
    std::string ip;
    uint16_t port{ 0 };

    // Identity
    std::array<uint8_t, 20> peerId{ 0 };
    std::string peerIdString;
    P2PApplication client{ P2PApplication::UNKNOWN };
    std::string clientVersion;

    // Connection
    bool isIncoming{ false };
    bool isEncrypted{ false };
    bool supportsExtensions{ false };

    // Transfer
    uint64_t bytesDownloaded{ 0 };
    uint64_t bytesUploaded{ 0 };
    double downloadRate{ 0.0 };
    double uploadRate{ 0.0 };

    // Timing
    std::chrono::system_clock::time_point connectedAt;
    std::chrono::system_clock::time_point lastActivity;

    // Geography
    std::string country;
    std::string asn;
};

/**
 * @struct TorrentInfo
 * @brief Information about a torrent.
 */
struct alignas(128) TorrentInfo {
    InfoHash infoHash;
    std::string name;
    uint64_t totalSize{ 0 };
    uint32_t pieceCount{ 0 };
    uint32_t pieceSize{ 0 };

    // Content
    std::vector<std::string> files;
    TorrentCategory category{ TorrentCategory::UNKNOWN };

    // Metadata
    std::string comment;
    std::string createdBy;
    std::chrono::system_clock::time_point creationDate;

    // Trackers
    std::vector<std::string> trackers;

    // Reputation
    bool isKnownMalicious{ false };
    bool isKnownLegitimate{ false };
    std::string malwareFamily;
    std::vector<std::string> threats;
};

/**
 * @struct SwarmInfo
 * @brief Information about a torrent swarm.
 */
struct alignas(128) SwarmInfo {
    // Identity
    InfoHash infoHash;
    std::optional<TorrentInfo> torrentInfo;

    // Peers
    uint32_t totalPeers{ 0 };
    uint32_t connectedPeers{ 0 };
    uint32_t seeders{ 0 };
    uint32_t leechers{ 0 };
    std::vector<PeerInfo> peers;

    // Local state
    uint32_t localProcessId{ 0 };
    std::string localProcessName;
    double downloadProgress{ 0.0 };
    bool isSeeding{ false };
    bool isDownloading{ false };

    // Traffic
    uint64_t bytesDownloaded{ 0 };
    uint64_t bytesUploaded{ 0 };
    double downloadRate{ 0.0 };
    double uploadRate{ 0.0 };

    // Timing
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastActivity;
};

/**
 * @struct P2PConnection
 * @brief Detected P2P connection.
 */
struct alignas(128) P2PConnection {
    // Identity
    uint64_t connectionId{ 0 };
    uint32_t processId{ 0 };
    std::string processName;
    std::wstring processPath;

    // Protocol
    P2PProtocol protocol{ P2PProtocol::UNKNOWN };
    P2PApplication application{ P2PApplication::UNKNOWN };
    std::string applicationVersion;

    // Network
    std::string localIP;
    uint16_t localPort{ 0 };
    std::string remoteIP;
    uint16_t remotePort{ 0 };
    bool isEncrypted{ false };

    // Torrent (if applicable)
    std::optional<InfoHash> infoHash;
    std::optional<TorrentInfo> torrentInfo;

    // Detection
    P2PConfidence confidence{ P2PConfidence::NONE };
    std::vector<std::string> detectionIndicators;

    // Traffic
    uint64_t bytesSent{ 0 };
    uint64_t bytesReceived{ 0 };
    double sendRate{ 0.0 };
    double receiveRate{ 0.0 };

    // Timing
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastActivity;

    // Threats
    std::vector<P2PThreatType> threats;
    bool isMalicious{ false };
};

/**
 * @struct DHTInfo
 * @brief DHT node information.
 */
struct alignas(64) DHTInfo {
    std::array<uint8_t, 20> nodeId{ 0 };
    std::string ip;
    uint16_t port{ 0 };

    // Statistics
    uint32_t queriesSent{ 0 };
    uint32_t queriesReceived{ 0 };
    uint32_t nodesInRoutingTable{ 0 };
    uint32_t torrentsTracked{ 0 };

    // Status
    bool isBootstrapped{ false };
    std::chrono::system_clock::time_point lastActivity;
};

/**
 * @struct P2PAlert
 * @brief Alert for P2P activity.
 */
struct alignas(256) P2PAlert {
    // Identity
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Detection
    P2PProtocol protocol{ P2PProtocol::UNKNOWN };
    P2PApplication application{ P2PApplication::UNKNOWN };
    P2PThreatType threatType{ P2PThreatType::NONE };

    // Process
    uint32_t processId{ 0 };
    std::string processName;
    std::wstring processPath;
    std::string username;

    // Torrent
    std::optional<InfoHash> infoHash;
    std::string torrentName;
    TorrentCategory category{ TorrentCategory::UNKNOWN };

    // Network
    std::string remoteIP;
    uint16_t remotePort{ 0 };
    uint32_t peerCount{ 0 };

    // Traffic
    uint64_t bytesTransferred{ 0 };
    double bandwidth{ 0.0 };

    // Description
    std::string description;
    std::vector<std::string> indicators;

    // Policy
    P2PPolicy appliedPolicy{ P2PPolicy::MONITOR };
    bool wasBlocked{ false };
    bool wasThrottled{ false };

    // Context
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct P2PMonitorConfig
 * @brief Configuration for P2P monitor.
 */
struct alignas(64) P2PMonitorConfig {
    // Main settings
    bool enabled{ true };
    P2PPolicy policy{ P2PPolicy::MONITOR };

    // Detection
    bool detectBitTorrent{ true };
    bool detectDHT{ true };
    bool detecteMule{ true };
    bool detectOtherP2P{ true };

    // Protocol-specific
    bool trackInfoHashes{ true };
    bool resolveMetadata{ true };
    bool trackPeers{ true };

    // Threat detection
    bool checkMaliciousHashes{ true };
    bool detectBotnets{ true };
    bool detectDataExfiltration{ true };

    // Policy enforcement
    uint64_t bandwidthLimitBps{ P2PMonitorConstants::DEFAULT_BANDWIDTH_LIMIT_BPS };
    uint32_t connectionLimit{ P2PMonitorConstants::DEFAULT_CONNECTION_LIMIT };
    bool blockMalicious{ true };

    // Exceptions
    std::vector<uint32_t> allowedProcessIds;
    std::vector<std::wstring> allowedPaths;
    std::vector<std::string> allowedInfoHashes;

    // Alerts
    bool alertOnDetection{ true };
    bool alertOnMalicious{ true };
    bool alertOnPolicyViolation{ true };

    // Logging
    bool logAllConnections{ false };
    bool logDetectionsOnly{ true };

    // Factory methods
    static P2PMonitorConfig CreateDefault() noexcept;
    static P2PMonitorConfig CreateCorporate() noexcept;       // Block all
    static P2PMonitorConfig CreateThrottle() noexcept;        // Limited bandwidth
    static P2PMonitorConfig CreateMonitorOnly() noexcept;
};

/**
 * @struct P2PMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) P2PMonitorStatistics {
    // Detection statistics
    std::atomic<uint64_t> totalConnectionsChecked{ 0 };
    std::atomic<uint64_t> p2pConnectionsDetected{ 0 };
    std::atomic<uint64_t> bittorrentConnections{ 0 };
    std::atomic<uint64_t> dhtQueries{ 0 };
    std::atomic<uint64_t> emuleConnections{ 0 };
    std::atomic<uint64_t> otherP2PConnections{ 0 };

    // Swarm statistics
    std::atomic<uint32_t> activeSwarms{ 0 };
    std::atomic<uint64_t> totalPeersTracked{ 0 };
    std::atomic<uint64_t> uniqueInfoHashes{ 0 };

    // Traffic statistics
    std::atomic<uint64_t> totalBytesP2P{ 0 };
    std::atomic<uint64_t> bytesDownloaded{ 0 };
    std::atomic<uint64_t> bytesUploaded{ 0 };

    // Threat statistics
    std::atomic<uint64_t> maliciousTorrents{ 0 };
    std::atomic<uint64_t> botnetActivityDetected{ 0 };
    std::atomic<uint64_t> policyViolations{ 0 };

    // Policy statistics
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    std::atomic<uint64_t> connectionsThrottled{ 0 };
    std::atomic<uint64_t> alertsGenerated{ 0 };

    // Application statistics
    std::atomic<uint64_t> qbittorrentDetected{ 0 };
    std::atomic<uint64_t> utorrentDetected{ 0 };
    std::atomic<uint64_t> transmissionDetected{ 0 };
    std::atomic<uint64_t> otherClientsDetected{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for P2P detection.
 */
using P2PDetectionCallback = std::function<void(const P2PConnection& connection)>;

/**
 * @brief Callback for P2P alerts.
 */
using P2PAlertCallback = std::function<void(const P2PAlert& alert)>;

/**
 * @brief Callback for swarm updates.
 */
using SwarmCallback = std::function<void(const SwarmInfo& swarm)>;

/**
 * @brief Callback for torrent detection.
 */
using TorrentCallback = std::function<void(const TorrentInfo& torrent)>;

/**
 * @brief Callback for DHT activity.
 */
using DHTCallback = std::function<void(const DHTInfo& dht)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class P2PMonitor
 * @brief Enterprise-grade P2P traffic monitoring and control.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& monitor = P2PMonitor::Instance();
 * 
 * // Initialize
 * auto config = P2PMonitorConfig::CreateCorporate();
 * monitor.Initialize(config);
 * 
 * // Register detection callback
 * monitor.RegisterDetectionCallback([](const P2PConnection& conn) {
 *     HandleP2PDetection(conn);
 * });
 * 
 * // Check for P2P
 * if (monitor.IsP2PTraffic(pid)) {
 *     TakeAction();
 * }
 * @endcode
 */
class P2PMonitor {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static P2PMonitor& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the P2P monitor.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const P2PMonitorConfig& config);

    /**
     * @brief Starts monitoring threads.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops monitoring threads.
     */
    void Stop();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if running.
     * @return True if active.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // P2P DETECTION
    // ========================================================================

    /**
     * @brief Check if process has P2P traffic.
     * @param pid Process ID.
     * @return True if P2P detected.
     */
    [[nodiscard]] bool IsP2PTraffic(uint32_t pid);

    /**
     * @brief Get P2P connections for process.
     * @param pid Process ID.
     * @return Vector of P2P connections.
     */
    [[nodiscard]] std::vector<P2PConnection> GetP2PConnections(uint32_t pid) const;

    /**
     * @brief Get all P2P connections.
     * @return Vector of all P2P connections.
     */
    [[nodiscard]] std::vector<P2PConnection> GetAllP2PConnections() const;

    /**
     * @brief Detect P2P protocol from packet.
     * @param packet Packet data.
     * @return Detected protocol.
     */
    [[nodiscard]] P2PProtocol DetectProtocol(std::span<const uint8_t> packet) const;

    // ========================================================================
    // SWARM MANAGEMENT
    // ========================================================================

    /**
     * @brief Get all tracked swarms.
     * @return Vector of swarm info.
     */
    [[nodiscard]] std::vector<SwarmInfo> GetActiveSwarms() const;

    /**
     * @brief Get swarm by infohash.
     * @param infoHash Torrent infohash.
     * @return Swarm info, or nullopt.
     */
    [[nodiscard]] std::optional<SwarmInfo> GetSwarm(const InfoHash& infoHash) const;

    /**
     * @brief Get swarm by infohash hex string.
     * @param infoHashHex Infohash as hex string.
     * @return Swarm info, or nullopt.
     */
    [[nodiscard]] std::optional<SwarmInfo> GetSwarm(const std::string& infoHashHex) const;

    // ========================================================================
    // TORRENT LOOKUP
    // ========================================================================

    /**
     * @brief Lookup torrent by infohash.
     * @param infoHash Torrent infohash.
     * @return Torrent info, or nullopt.
     */
    [[nodiscard]] std::optional<TorrentInfo> LookupTorrent(const InfoHash& infoHash) const;

    /**
     * @brief Check if infohash is known malicious.
     * @param infoHash Torrent infohash.
     * @return True if malicious.
     */
    [[nodiscard]] bool IsKnownMalicious(const InfoHash& infoHash) const;

    /**
     * @brief Add malicious infohash.
     * @param infoHash Infohash to mark malicious.
     * @param reason Reason.
     */
    void AddMaliciousHash(const InfoHash& infoHash, const std::string& reason);

    // ========================================================================
    // DHT MONITORING
    // ========================================================================

    /**
     * @brief Get DHT info for process.
     * @param pid Process ID.
     * @return DHT info, or nullopt.
     */
    [[nodiscard]] std::optional<DHTInfo> GetDHTInfo(uint32_t pid) const;

    // ========================================================================
    // TRAFFIC ANALYSIS
    // ========================================================================

    /**
     * @brief Feed packet for analysis.
     * @param connectionId Connection ID.
     * @param packet Packet data.
     */
    void FeedPacket(uint64_t connectionId, std::span<const uint8_t> packet);

    /**
     * @brief Get P2P bandwidth usage.
     * @return Pair of (download_bps, upload_bps).
     */
    [[nodiscard]] std::pair<uint64_t, uint64_t> GetBandwidthUsage() const noexcept;

    // ========================================================================
    // POLICY ENFORCEMENT
    // ========================================================================

    /**
     * @brief Block P2P for process.
     * @param pid Process ID.
     * @return True if blocked.
     */
    bool BlockProcess(uint32_t pid);

    /**
     * @brief Unblock P2P for process.
     * @param pid Process ID.
     * @return True if unblocked.
     */
    bool UnblockProcess(uint32_t pid);

    /**
     * @brief Throttle P2P bandwidth.
     * @param pid Process ID.
     * @param limitBps Bandwidth limit in bytes/sec.
     * @return True if applied.
     */
    bool ThrottleProcess(uint32_t pid, uint64_t limitBps);

    /**
     * @brief Set global policy.
     * @param policy Policy to apply.
     */
    void SetPolicy(P2PPolicy policy);

    /**
     * @brief Get current policy.
     * @return Current policy.
     */
    [[nodiscard]] P2PPolicy GetPolicy() const noexcept;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterDetectionCallback(P2PDetectionCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(P2PAlertCallback callback);
    [[nodiscard]] uint64_t RegisterSwarmCallback(SwarmCallback callback);
    [[nodiscard]] uint64_t RegisterTorrentCallback(TorrentCallback callback);
    [[nodiscard]] uint64_t RegisterDHTCallback(DHTCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const P2PMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    P2PMonitor();
    ~P2PMonitor();

    P2PMonitor(const P2PMonitor&) = delete;
    P2PMonitor& operator=(const P2PMonitor&) = delete;

    std::unique_ptr<P2PMonitorImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
