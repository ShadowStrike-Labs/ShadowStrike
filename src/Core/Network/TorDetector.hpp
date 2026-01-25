/**
 * ============================================================================
 * ShadowStrike Core Network - TOR DETECTOR (The Onion Watch)
 * ============================================================================
 *
 * @file TorDetector.hpp
 * @brief Enterprise-grade Tor network detection and monitoring engine.
 *
 * This module provides comprehensive detection of The Onion Router (Tor)
 * network usage through multiple detection methods including node lists,
 * traffic fingerprinting, process identification, and behavioral analysis.
 *
 * Key Capabilities:
 * =================
 * 1. NODE LIST DETECTION
 *    - Tor consensus directory monitoring
 *    - Exit node detection
 *    - Relay node detection
 *    - Bridge node detection
 *    - Guard node identification
 *
 * 2. TRAFFIC FINGERPRINTING
 *    - Cell size analysis (512 bytes)
 *    - Timing pattern detection
 *    - TLS fingerprinting
 *    - Protocol anomaly detection
 *    - Circuit building patterns
 *
 * 3. PROCESS DETECTION
 *    - Tor browser detection
 *    - tor.exe process identification
 *    - Pluggable transport detection (obfs4, meek)
 *    - Embedded Tor detection
 *    - Hidden Tor installations
 *
 * 4. BEHAVIORAL ANALYSIS
 *    - Connection pattern analysis
 *    - Onion service access detection
 *    - Directory authority communication
 *    - Circuit establishment patterns
 *
 * 5. POLICY ENFORCEMENT
 *    - Tor blocking (configurable)
 *    - Exit node blocking
 *    - Bridge bypass detection
 *    - Policy exception management
 *
 * Detection Architecture:
 * =======================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        TorDetector                                  │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │NodeListMgr   │  │TrafficAnalyz │  │    ProcessDetector       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Exit Nodes │  │ - Cell Size  │  │ - tor.exe                │  │
 *   │  │ - Relays     │  │ - Timing     │  │ - Tor Browser            │  │
 *   │  │ - Bridges    │  │ - TLS FP     │  │ - Pluggable Transport    │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │BehaviorAnalyz│  │PolicyEnforce │  │    ThreatIntelIntegr     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Patterns   │  │ - Blocking   │  │ - Node Reputation        │  │
 *   │  │ - Circuits   │  │ - Exceptions │  │ - Malicious Exits        │  │
 *   │  │ - .onion     │  │ - Logging    │  │ - Abuse Reports          │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Tor Network Components Detected:
 * ================================
 * - Directory Authorities (hardcoded)
 * - Guard/Entry Nodes
 * - Middle Relays
 * - Exit Nodes
 * - Bridge Nodes (obfs4, meek, snowflake)
 * - Hidden Services (.onion)
 * - Tor Browser
 * - Standalone Tor daemon
 *
 * Pluggable Transports Detected:
 * ==============================
 * - obfs4 (obfuscation)
 * - meek (domain fronting)
 * - snowflake (WebRTC)
 * - fte (format transforming)
 * - scramblesuit
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1090.003: Proxy: Multi-hop Proxy
 * - T1188: Multi-hop Proxy
 * - T1573: Encrypted Channel
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Node list updates are atomic
 * - Concurrent detection supported
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see VPNDetector.hpp for VPN detection
 * @see NetworkMonitor.hpp for traffic monitoring
 */

#pragma once

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
class TorDetectorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace TorDetectorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Tor protocol constants
    constexpr size_t TOR_CELL_SIZE = 512;                // Standard Tor cell
    constexpr size_t TOR_CELL_SIZE_WIDE = 514;           // Cell + 2 byte circuit ID
    constexpr uint16_t TOR_DEFAULT_PORT = 9001;          // ORPort
    constexpr uint16_t TOR_DIR_PORT = 9030;              // DirPort
    constexpr uint16_t TOR_SOCKS_PORT = 9050;            // SOCKS proxy
    constexpr uint16_t TOR_CONTROL_PORT = 9051;          // Control port
    constexpr uint16_t TOR_BROWSER_PORT = 9150;          // Tor Browser SOCKS

    // Detection thresholds
    constexpr double TRAFFIC_CONFIDENCE_THRESHOLD = 0.75;
    constexpr uint32_t MIN_CELLS_FOR_DETECTION = 10;
    constexpr double CELL_SIZE_TOLERANCE = 0.05;         // 5% variance

    // Node list management
    constexpr uint32_t NODE_LIST_UPDATE_INTERVAL_HOURS = 1;
    constexpr size_t MAX_CACHED_NODES = 100000;
    constexpr size_t MAX_EXIT_NODES = 10000;
    constexpr size_t MAX_BRIDGE_NODES = 5000;

    // Process detection
    constexpr size_t TOR_SIGNATURE_SIZE = 256;

    // Directory Authorities (v3)
    constexpr uint8_t DIR_AUTHORITY_COUNT = 9;

}  // namespace TorDetectorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum TorNodeType
 * @brief Type of Tor network node.
 */
enum class TorNodeType : uint8_t {
    UNKNOWN = 0,
    DIRECTORY_AUTHORITY = 1,
    GUARD_NODE = 2,                // Entry guard
    MIDDLE_RELAY = 3,
    EXIT_NODE = 4,
    BRIDGE = 5,
    HIDDEN_SERVICE = 6,
    CLIENT = 7
};

/**
 * @enum TorFlags
 * @brief Tor relay flags.
 */
enum class TorFlags : uint16_t {
    NONE = 0,
    AUTHORITY = 1 << 0,
    BAD_EXIT = 1 << 1,
    EXIT = 1 << 2,
    FAST = 1 << 3,
    GUARD = 1 << 4,
    HSDIR = 1 << 5,
    NO_ED_CONSENSUS = 1 << 6,
    STABLE = 1 << 7,
    STALE_DESC = 1 << 8,
    RUNNING = 1 << 9,
    VALID = 1 << 10,
    V2DIR = 1 << 11
};

inline TorFlags operator|(TorFlags a, TorFlags b) {
    return static_cast<TorFlags>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}

inline TorFlags operator&(TorFlags a, TorFlags b) {
    return static_cast<TorFlags>(static_cast<uint16_t>(a) & static_cast<uint16_t>(b));
}

/**
 * @enum PluggableTransport
 * @brief Pluggable transport types.
 */
enum class PluggableTransport : uint8_t {
    NONE = 0,
    OBFS4 = 1,
    MEEK = 2,
    SNOWFLAKE = 3,
    FTE = 4,
    SCRAMBLESUIT = 5,
    WEBTUNNEL = 6,
    UNKNOWN = 255
};

/**
 * @enum DetectionMethod
 * @brief How Tor was detected.
 */
enum class DetectionMethod : uint8_t {
    NONE = 0,
    NODE_LIST = 1,                 // IP matched known node
    TRAFFIC_PATTERN = 2,           // Cell size/timing
    PROCESS_DETECTION = 3,         // Tor process found
    TLS_FINGERPRINT = 4,           // TLS characteristics
    BEHAVIORAL = 5,                // Connection patterns
    DIRECTORY_AUTH = 6,            // Communication with DA
    COMBINED = 7                   // Multiple methods
};

/**
 * @enum TorPolicy
 * @brief Policy for Tor traffic.
 */
enum class TorPolicy : uint8_t {
    ALLOW = 0,                     // Allow all Tor
    MONITOR = 1,                   // Allow but log
    BLOCK_EXIT = 2,                // Block exit nodes only
    BLOCK_ALL = 3,                 // Block all Tor traffic
    ALERT_ONLY = 4                 // No blocking, alerts only
};

/**
 * @enum DetectionConfidence
 * @brief Confidence level of detection.
 */
enum class TorConfidence : uint8_t {
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
 * @struct TorNodeInfo
 * @brief Information about a Tor node.
 */
struct alignas(128) TorNodeInfo {
    // Identity
    std::string ipAddress;
    uint16_t orPort{ 0 };
    uint16_t dirPort{ 0 };
    std::string fingerprint;               // 40 char hex
    std::string nickname;

    // Classification
    TorNodeType type{ TorNodeType::UNKNOWN };
    TorFlags flags{ TorFlags::NONE };

    // Bandwidth
    uint64_t bandwidth{ 0 };               // bytes/sec
    uint64_t observedBandwidth{ 0 };

    // Versioning
    std::string version;
    std::string platform;

    // Exit policy
    bool allowsExit{ false };
    std::vector<std::string> exitPolicy;

    // Geography
    std::string country;
    std::string asn;
    std::string asName;

    // Timestamps
    std::chrono::system_clock::time_point publishedAt;
    std::chrono::system_clock::time_point lastSeen;

    // Reputation
    bool isBadExit{ false };
    bool isKnownMalicious{ false };
    std::vector<std::string> maliciousReasons;

    // Contact
    std::string contact;
};

/**
 * @struct TorTrafficAnalysis
 * @brief Traffic pattern analysis for Tor detection.
 */
struct alignas(64) TorTrafficAnalysis {
    // Detection
    bool isTor{ false };
    TorConfidence confidence{ TorConfidence::NONE };
    DetectionMethod method{ DetectionMethod::NONE };

    // Cell analysis
    uint64_t totalPackets{ 0 };
    uint64_t cellSizedPackets{ 0 };
    double cellSizeRatio{ 0.0 };

    // Size distribution
    double avgPacketSize{ 0.0 };
    double stdDevPacketSize{ 0.0 };
    double cellSizeVariance{ 0.0 };

    // Timing
    double avgInterPacketMs{ 0.0 };
    bool hasCircuitBuilding{ false };

    // TLS analysis
    bool hasTorTLS{ false };
    std::string tlsFingerprint;

    // Patterns
    std::vector<std::string> matchedPatterns;
};

/**
 * @struct TorProcessInfo
 * @brief Information about detected Tor process.
 */
struct alignas(128) TorProcessInfo {
    uint32_t processId{ 0 };
    std::string processName;
    std::wstring executablePath;
    std::string commandLine;

    // Classification
    bool isTorBrowser{ false };
    bool isTorDaemon{ false };
    bool isPluggableTransport{ false };
    PluggableTransport transportType{ PluggableTransport::NONE };

    // Version
    std::string version;
    std::string buildDate;

    // Network
    std::vector<uint16_t> listeningPorts;
    std::vector<std::string> connectedNodes;

    // Status
    bool isRunning{ true };
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point detectedAt;

    // Memory
    uint64_t memoryUsage{ 0 };
};

/**
 * @struct TorConnection
 * @brief Detected Tor connection.
 */
struct alignas(128) TorConnection {
    // Connection identity
    uint64_t connectionId{ 0 };
    uint32_t processId{ 0 };
    std::string processName;

    // Network
    std::string localIP;
    uint16_t localPort{ 0 };
    std::string remoteIP;
    uint16_t remotePort{ 0 };

    // Detection
    bool isTor{ false };
    TorConfidence confidence{ TorConfidence::NONE };
    DetectionMethod method{ DetectionMethod::NONE };
    std::vector<DetectionMethod> allMethods;

    // Node info (if identified)
    std::optional<TorNodeInfo> nodeInfo;
    TorNodeType nodeType{ TorNodeType::UNKNOWN };

    // Circuit (if detectable)
    bool isCircuitBuilding{ false };
    uint32_t circuitId{ 0 };

    // Pluggable transport
    bool usesPluggableTransport{ false };
    PluggableTransport transport{ PluggableTransport::NONE };

    // Traffic
    uint64_t bytesSent{ 0 };
    uint64_t bytesReceived{ 0 };
    TorTrafficAnalysis trafficAnalysis;

    // Timing
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastActivity;

    // Onion service
    bool accessingOnionService{ false };
    std::string onionAddress;
};

/**
 * @struct TorAlert
 * @brief Alert for Tor detection.
 */
struct alignas(256) TorAlert {
    // Identity
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Detection
    DetectionMethod method{ DetectionMethod::NONE };
    TorConfidence confidence{ TorConfidence::NONE };

    // Subject
    uint32_t processId{ 0 };
    std::string processName;
    std::wstring processPath;
    std::string username;

    // Connection
    std::string remoteIP;
    uint16_t remotePort{ 0 };
    TorNodeType nodeType{ TorNodeType::UNKNOWN };
    std::string nodeFingerprint;

    // Description
    std::string description;
    std::vector<std::string> indicators;

    // Policy
    TorPolicy appliedPolicy{ TorPolicy::MONITOR };
    bool wasBlocked{ false };

    // Context
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct TorDetectorConfig
 * @brief Configuration for Tor detector.
 */
struct alignas(64) TorDetectorConfig {
    // Main settings
    bool enabled{ true };
    TorPolicy policy{ TorPolicy::MONITOR };

    // Detection methods
    bool enableNodeListDetection{ true };
    bool enableTrafficAnalysis{ true };
    bool enableProcessDetection{ true };
    bool enableTLSFingerprinting{ true };
    bool enableBehavioralAnalysis{ true };

    // Node list settings
    bool autoUpdateNodeList{ true };
    uint32_t nodeListUpdateIntervalHours{ TorDetectorConstants::NODE_LIST_UPDATE_INTERVAL_HOURS };
    std::wstring nodeListCachePath;

    // Detection thresholds
    double trafficConfidenceThreshold{ TorDetectorConstants::TRAFFIC_CONFIDENCE_THRESHOLD };
    uint32_t minCellsForDetection{ TorDetectorConstants::MIN_CELLS_FOR_DETECTION };

    // Blocking settings
    bool blockExitNodes{ false };
    bool blockAllTor{ false };
    bool blockPluggableTransports{ false };
    bool blockOnionAccess{ false };

    // Exceptions
    std::vector<uint32_t> allowedProcessIds;
    std::vector<std::string> allowedUsers;
    std::vector<std::wstring> allowedPaths;

    // Alerts
    bool alertOnDetection{ true };
    bool alertOnBlockedConnection{ true };
    bool alertOnNewProcess{ true };

    // Logging
    bool logAllConnections{ false };
    bool logDetectionsOnly{ true };

    // Factory methods
    static TorDetectorConfig CreateDefault() noexcept;
    static TorDetectorConfig CreateHighSecurity() noexcept;
    static TorDetectorConfig CreateMonitorOnly() noexcept;
    static TorDetectorConfig CreateBlockAll() noexcept;
};

/**
 * @struct TorDetectorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) TorDetectorStatistics {
    // Detection statistics
    std::atomic<uint64_t> totalConnectionsChecked{ 0 };
    std::atomic<uint64_t> torConnectionsDetected{ 0 };
    std::atomic<uint64_t> exitNodesDetected{ 0 };
    std::atomic<uint64_t> guardNodesDetected{ 0 };
    std::atomic<uint64_t> bridgesDetected{ 0 };

    // Process statistics
    std::atomic<uint64_t> torProcessesDetected{ 0 };
    std::atomic<uint64_t> torBrowsersDetected{ 0 };
    std::atomic<uint64_t> pluggableTransportsDetected{ 0 };

    // Traffic statistics
    std::atomic<uint64_t> packetsAnalyzed{ 0 };
    std::atomic<uint64_t> cellSizedPackets{ 0 };

    // Detection methods
    std::atomic<uint64_t> nodeListMatches{ 0 };
    std::atomic<uint64_t> trafficPatternMatches{ 0 };
    std::atomic<uint64_t> processMatches{ 0 };
    std::atomic<uint64_t> tlsFingerprintMatches{ 0 };

    // Policy statistics
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    std::atomic<uint64_t> alertsGenerated{ 0 };

    // Node list
    std::atomic<uint32_t> knownExitNodes{ 0 };
    std::atomic<uint32_t> knownRelays{ 0 };
    std::atomic<uint32_t> knownBridges{ 0 };

    // Timing
    std::chrono::system_clock::time_point lastNodeListUpdate;

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for Tor detection.
 */
using TorDetectionCallback = std::function<void(const TorConnection& connection)>;

/**
 * @brief Callback for Tor alerts.
 */
using TorAlertCallback = std::function<void(const TorAlert& alert)>;

/**
 * @brief Callback for Tor process detection.
 */
using TorProcessCallback = std::function<void(const TorProcessInfo& process)>;

/**
 * @brief Callback for node list updates.
 */
using NodeListUpdateCallback = std::function<void(
    uint32_t exitNodes,
    uint32_t relays,
    uint32_t bridges
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class TorDetector
 * @brief Enterprise-grade Tor network detection.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& detector = TorDetector::Instance();
 * 
 * // Initialize
 * auto config = TorDetectorConfig::CreateHighSecurity();
 * config.policy = TorPolicy::BLOCK_ALL;
 * detector.Initialize(config);
 * 
 * // Register detection callback
 * detector.RegisterDetectionCallback([](const TorConnection& conn) {
 *     HandleTorDetection(conn);
 * });
 * 
 * // Check connection
 * if (detector.IsTorTraffic(remoteIP)) {
 *     BlockConnection();
 * }
 * @endcode
 */
class TorDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static TorDetector& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the Tor detector.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const TorDetectorConfig& config);

    /**
     * @brief Starts detection threads.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops detection threads.
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
    // IP DETECTION
    // ========================================================================

    /**
     * @brief Check if connection is using Tor network.
     * @param remoteIp Remote IP address.
     * @return True if Tor traffic detected.
     */
    [[nodiscard]] bool IsTorTraffic(const std::string& remoteIp);

    /**
     * @brief Check if IP is known Tor node.
     * @param ip IP address.
     * @return Node info if found.
     */
    [[nodiscard]] std::optional<TorNodeInfo> GetNodeInfo(const std::string& ip) const;

    /**
     * @brief Check if IP is exit node.
     * @param ip IP address.
     * @return True if exit node.
     */
    [[nodiscard]] bool IsExitNode(const std::string& ip) const;

    /**
     * @brief Check if IP is guard node.
     * @param ip IP address.
     * @return True if guard node.
     */
    [[nodiscard]] bool IsGuardNode(const std::string& ip) const;

    /**
     * @brief Check if IP is bridge.
     * @param ip IP address.
     * @return True if bridge.
     */
    [[nodiscard]] bool IsBridge(const std::string& ip) const;

    // ========================================================================
    // PROCESS DETECTION
    // ========================================================================

    /**
     * @brief Check if process is Tor.
     * @param pid Process ID.
     * @return True if Tor process.
     */
    [[nodiscard]] bool IsTorProcess(uint32_t pid);

    /**
     * @brief Get Tor process information.
     * @param pid Process ID.
     * @return Process info if Tor.
     */
    [[nodiscard]] std::optional<TorProcessInfo> GetTorProcessInfo(uint32_t pid) const;

    /**
     * @brief Get all detected Tor processes.
     * @return Vector of Tor processes.
     */
    [[nodiscard]] std::vector<TorProcessInfo> GetAllTorProcesses() const;

    // ========================================================================
    // TRAFFIC ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze traffic for Tor patterns.
     * @param connectionId Connection ID.
     * @return Traffic analysis.
     */
    [[nodiscard]] TorTrafficAnalysis AnalyzeTraffic(uint64_t connectionId) const;

    /**
     * @brief Feed packet for analysis.
     * @param connectionId Connection ID.
     * @param packetSize Packet size.
     */
    void FeedPacket(uint64_t connectionId, size_t packetSize);

    // ========================================================================
    // CONNECTION MANAGEMENT
    // ========================================================================

    /**
     * @brief Get all detected Tor connections.
     * @return Vector of Tor connections.
     */
    [[nodiscard]] std::vector<TorConnection> GetTorConnections() const;

    /**
     * @brief Get connection by ID.
     * @param connectionId Connection ID.
     * @return Connection info if found.
     */
    [[nodiscard]] std::optional<TorConnection> GetConnection(uint64_t connectionId) const;

    // ========================================================================
    // NODE LIST MANAGEMENT
    // ========================================================================

    /**
     * @brief Updates Tor node list from consensus.
     * @return True if updated.
     */
    bool UpdateNodeList();

    /**
     * @brief Loads node list from file.
     * @param path Path to node list file.
     * @return Number of nodes loaded.
     */
    size_t LoadNodeList(const std::wstring& path);

    /**
     * @brief Saves node list to file.
     * @param path Path to save.
     * @return True if saved.
     */
    bool SaveNodeList(const std::wstring& path) const;

    /**
     * @brief Gets node list statistics.
     * @return Tuple of (exit_count, relay_count, bridge_count).
     */
    [[nodiscard]] std::tuple<uint32_t, uint32_t, uint32_t> GetNodeCounts() const noexcept;

    // ========================================================================
    // POLICY MANAGEMENT
    // ========================================================================

    /**
     * @brief Sets Tor policy.
     * @param policy Policy to apply.
     */
    void SetPolicy(TorPolicy policy);

    /**
     * @brief Gets current policy.
     * @return Current policy.
     */
    [[nodiscard]] TorPolicy GetPolicy() const noexcept;

    /**
     * @brief Adds exception for process.
     * @param pid Process ID.
     */
    void AddProcessException(uint32_t pid);

    /**
     * @brief Removes process exception.
     * @param pid Process ID.
     */
    void RemoveProcessException(uint32_t pid);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterDetectionCallback(TorDetectionCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(TorAlertCallback callback);
    [[nodiscard]] uint64_t RegisterProcessCallback(TorProcessCallback callback);
    [[nodiscard]] uint64_t RegisterNodeListCallback(NodeListUpdateCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const TorDetectorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    TorDetector();
    ~TorDetector();

    TorDetector(const TorDetector&) = delete;
    TorDetector& operator=(const TorDetector&) = delete;

    std::unique_ptr<TorDetectorImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
