/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - POOL CONNECTION DETECTOR
 * ============================================================================
 *
 * @file PoolConnectionDetector.hpp
 * @brief Enterprise-grade network-layer detection of cryptocurrency mining
 *        pool communications and Stratum protocol traffic.
 *
 * Monitors network traffic for mining pool connections, Stratum protocol
 * signatures, JSON-RPC mining commands, and known pool endpoints.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. STRATUM PROTOCOL DETECTION
 *    - Stratum v1 protocol
 *    - Stratum v2 protocol
 *    - JSON-RPC mining commands
 *    - mining.subscribe/authorize
 *    - mining.submit/notify
 *
 * 2. POOL ENDPOINT DETECTION
 *    - Known pool IP addresses
 *    - Pool domain resolution
 *    - Pool port fingerprinting
 *    - TLS/SSL pool connections
 *    - Proxy pool detection
 *
 * 3. WALLET ADDRESS EXTRACTION
 *    - Login payload parsing
 *    - Worker name extraction
 *    - Pool password/token
 *    - Wallet format validation
 *
 * 4. TRAFFIC ANALYSIS
 *    - Share submission patterns
 *    - Job notification frequency
 *    - Connection persistence
 *    - Bandwidth characteristics
 *    - Packet timing analysis
 *
 * 5. PROTOCOL VARIANTS
 *    - Stratum (standard)
 *    - NiceHash stratum
 *    - EthProxy protocol
 *    - GetWork (legacy)
 *    - GetBlockTemplate
 *
 * 6. EVASION DETECTION
 *    - Encrypted stratum
 *    - Non-standard ports
 *    - Domain fronting
 *    - DNS over HTTPS pools
 *    - TOR pool connections
 *
 * INTEGRATION:
 * ============
 * - Utils::NetworkUtils for traffic capture
 * - ThreatIntel for pool blacklists
 * - CryptoMinerDetector for correlation
 *
 * @note Requires packet capture capability.
 * @note Deep packet inspection for non-encrypted traffic.
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
#include <span>
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
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::CryptoMiners {
    class PoolConnectionDetectorImpl;
}

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace PoolDetectorConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Common stratum ports
    inline constexpr uint16_t STRATUM_PORTS[] = {
        3333, 3334, 3335, 3336, 4444, 5555, 7777, 8888, 9999,
        14433, 14444, 45560, 45700
    };
    
    /// @brief Maximum connections to track
    inline constexpr size_t MAX_TRACKED_CONNECTIONS = 4096;
    
    /// @brief Maximum known pools
    inline constexpr size_t MAX_KNOWN_POOLS = 8192;
    
    /// @brief Connection timeout (seconds)
    inline constexpr uint32_t CONNECTION_TIMEOUT_SECS = 30;
    
    /// @brief Payload inspection limit (bytes)
    inline constexpr size_t MAX_PAYLOAD_INSPECT_SIZE = 65536;

}  // namespace PoolDetectorConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Mining protocol type
 */
enum class PoolProtocolType : uint8_t {
    Unknown             = 0,
    Stratum             = 1,    ///< Standard Stratum v1
    StratumV2           = 2,    ///< Stratum v2
    NiceHashStratum     = 3,    ///< NiceHash variant
    EthProxy            = 4,    ///< Ethereum proxy
    GetWork             = 5,    ///< Legacy getwork
    GetBlockTemplate    = 6,    ///< getblocktemplate
    EthereumStratum     = 7,    ///< eth-proxy stratum
    CryptoNightStratum  = 8     ///< CryptoNight stratum
};

/**
 * @brief Pool status
 */
enum class PoolStatus : uint8_t {
    Unknown         = 0,
    KnownPublic     = 1,    ///< Legitimate public pool
    KnownMalicious  = 2,    ///< Used by malware
    Private         = 3,    ///< Unknown/private pool
    P2P             = 4,    ///< P2P mining network
    Proxy           = 5     ///< Mining proxy
};

/**
 * @brief Connection state
 */
enum class ConnectionState : uint8_t {
    Unknown         = 0,
    Connecting      = 1,
    Connected       = 2,
    Authenticating  = 3,
    Authenticated   = 4,
    Mining          = 5,
    Disconnected    = 6,
    Blocked         = 7
};

/**
 * @brief Stratum command type
 */
enum class StratumCommand : uint8_t {
    Unknown             = 0,
    Subscribe           = 1,    ///< mining.subscribe
    Authorize           = 2,    ///< mining.authorize
    Submit              = 3,    ///< mining.submit
    Notify              = 4,    ///< mining.notify
    SetDifficulty       = 5,    ///< mining.set_difficulty
    SetExtranonce       = 6,    ///< mining.set_extranonce
    Reconnect           = 7,    ///< client.reconnect
    GetVersion          = 8,    ///< client.get_version
    EthSubmitWork       = 9,    ///< eth_submitWork
    EthSubmitHashrate   = 10    ///< eth_submitHashrate
};

/**
 * @brief Cryptocurrency being mined
 */
enum class MinedCryptocurrency : uint8_t {
    Unknown     = 0,
    Bitcoin     = 1,
    Ethereum    = 2,
    Monero      = 3,
    Litecoin    = 4,
    Ravencoin   = 5,
    Zcash       = 6,
    EthClassic  = 7,
    Ergo        = 8,
    Other       = 255
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Pool endpoint info
 */
struct PoolEndpointInfo {
    /// @brief Pool address (hostname)
    std::string address;
    
    /// @brief Pool port
    uint16_t port = 0;
    
    /// @brief Resolved IP addresses
    std::vector<std::string> ipAddresses;
    
    /// @brief Pool name
    std::string poolName;
    
    /// @brief Pool operator
    std::string poolOperator;
    
    /// @brief Pool status
    PoolStatus status = PoolStatus::Unknown;
    
    /// @brief Supported protocols
    std::vector<PoolProtocolType> protocols;
    
    /// @brief Supported cryptocurrencies
    std::vector<MinedCryptocurrency> cryptocurrencies;
    
    /// @brief Is TLS/SSL required
    bool requiresTLS = false;
    
    /// @brief Is on blacklist
    bool isBlacklisted = false;
    
    /// @brief Threat intel source
    std::string threatIntelSource;
    
    /// @brief Last seen time
    SystemTimePoint lastSeen;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Pool connection info
 */
struct PoolConnectionInfo {
    /// @brief Connection ID
    std::string connectionId;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Local IP
    std::string localIP;
    
    /// @brief Local port
    uint16_t localPort = 0;
    
    /// @brief Remote IP
    std::string remoteIP;
    
    /// @brief Remote port
    uint16_t remotePort = 0;
    
    /// @brief Remote hostname
    std::string remoteHostname;
    
    /// @brief Pool info
    PoolEndpointInfo poolInfo;
    
    /// @brief Connection state
    ConnectionState state = ConnectionState::Unknown;
    
    /// @brief Protocol detected
    PoolProtocolType protocol = PoolProtocolType::Unknown;
    
    /// @brief Cryptocurrency
    MinedCryptocurrency cryptocurrency = MinedCryptocurrency::Unknown;
    
    /// @brief Is encrypted (TLS)
    bool isEncrypted = false;
    
    /// @brief Wallet address (if extracted)
    std::string walletAddress;
    
    /// @brief Worker name (if extracted)
    std::string workerName;
    
    /// @brief Pool password/token
    std::string poolPassword;
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Shares submitted
    uint32_t sharesSubmitted = 0;
    
    /// @brief Shares accepted
    uint32_t sharesAccepted = 0;
    
    /// @brief Shares rejected
    uint32_t sharesRejected = 0;
    
    /// @brief Connection time
    SystemTimePoint connectionTime;
    
    /// @brief Duration (seconds)
    uint32_t durationSecs = 0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Stratum message
 */
struct StratumMessage {
    /// @brief Message ID
    uint64_t messageId = 0;
    
    /// @brief Command type
    StratumCommand command = StratumCommand::Unknown;
    
    /// @brief Method name (raw)
    std::string method;
    
    /// @brief Parameters (JSON string)
    std::string params;
    
    /// @brief Result (JSON string)
    std::string result;
    
    /// @brief Is request (vs response)
    bool isRequest = true;
    
    /// @brief Has error
    bool hasError = false;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Raw message
    std::string rawMessage;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection result
 */
struct PoolDetectionResult {
    /// @brief Detection ID
    std::string detectionId;
    
    /// @brief Is pool connection detected
    bool isPoolConnectionDetected = false;
    
    /// @brief Connection info
    PoolConnectionInfo connectionInfo;
    
    /// @brief Stratum messages captured
    std::vector<StratumMessage> stratumMessages;
    
    /// @brief Is confirmed mining
    bool isConfirmedMining = false;
    
    /// @brief Confidence (0-100)
    double confidenceScore = 0.0;
    
    /// @brief Was blocked
    bool wasBlocked = false;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct PoolDetectorStatistics {
    std::atomic<uint64_t> connectionsAnalyzed{0};
    std::atomic<uint64_t> poolConnectionsDetected{0};
    std::atomic<uint64_t> stratumSessionsDetected{0};
    std::atomic<uint64_t> connectionsBlocked{0};
    std::atomic<uint64_t> walletsExtracted{0};
    std::atomic<uint64_t> sharesDetected{0};
    std::array<std::atomic<uint64_t>, 16> byProtocol{};
    std::array<std::atomic<uint64_t>, 16> byCrypto{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct PoolConnectionDetectorConfiguration {
    /// @brief Enable Stratum detection
    bool enableStratumDetection = true;
    
    /// @brief Enable deep packet inspection
    bool enableDeepPacketInspection = true;
    
    /// @brief Block stratum traffic
    bool blockStratumTraffic = true;
    
    /// @brief Block known malicious pools
    bool blockMaliciousPools = true;
    
    /// @brief Monitor ports (empty = all stratum ports)
    std::vector<uint16_t> monitorPorts;
    
    /// @brief Extract wallet addresses
    bool extractWalletAddresses = true;
    
    /// @brief Log stratum messages
    bool logStratumMessages = true;
    
    /// @brief Pool blacklist path
    std::wstring poolBlacklistPath;
    
    /// @brief Whitelisted pools
    std::vector<std::string> whitelistedPools;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using PoolConnectionCallback = std::function<void(const PoolConnectionInfo&)>;
using StratumDetectedCallback = std::function<void(const PoolDetectionResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// POOL CONNECTION DETECTOR CLASS
// ============================================================================

/**
 * @class PoolConnectionDetector
 * @brief Enterprise-grade mining pool connection detection
 */
class PoolConnectionDetector final {
public:
    [[nodiscard]] static PoolConnectionDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PoolConnectionDetector(const PoolConnectionDetector&) = delete;
    PoolConnectionDetector& operator=(const PoolConnectionDetector&) = delete;
    PoolConnectionDetector(PoolConnectionDetector&&) = delete;
    PoolConnectionDetector& operator=(PoolConnectionDetector&&) = delete;

    [[nodiscard]] bool Initialize(const PoolConnectionDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool Start();
    [[nodiscard]] bool Stop();
    void Pause();
    void Resume();
    
    [[nodiscard]] bool UpdateConfiguration(const PoolConnectionDetectorConfiguration& config);
    [[nodiscard]] PoolConnectionDetectorConfiguration GetConfiguration() const;
    
    /// @brief Analyze payload for Stratum traffic
    [[nodiscard]] bool IsStratumTraffic(std::span<const uint8_t> payload);
    
    /// @brief Parse Stratum message
    [[nodiscard]] std::optional<StratumMessage> ParseStratumMessage(
        std::span<const uint8_t> payload);
    
    /// @brief Check if endpoint is known pool
    [[nodiscard]] bool IsPoolEndpoint(const std::string& ip, uint16_t port) const;
    
    /// @brief Check if hostname is known pool
    [[nodiscard]] bool IsPoolHostname(const std::string& hostname) const;
    
    /// @brief Get pool info
    [[nodiscard]] std::optional<PoolEndpointInfo> GetPoolInfo(
        const std::string& address, uint16_t port = 0) const;
    
    /// @brief Extract wallet address from payload
    [[nodiscard]] std::optional<std::string> ExtractWalletAddress(
        std::span<const uint8_t> payload);
    
    /// @brief Extract worker name from payload
    [[nodiscard]] std::optional<std::string> ExtractWorkerName(
        std::span<const uint8_t> payload);
    
    /// @brief Get active pool connections
    [[nodiscard]] std::vector<PoolConnectionInfo> GetActiveConnections() const;
    
    /// @brief Get connections for process
    [[nodiscard]] std::vector<PoolConnectionInfo> GetProcessConnections(
        uint32_t processId) const;
    
    /// @brief Block pool address
    [[nodiscard]] bool BlockPoolAddress(const std::string& address);
    
    /// @brief Unblock pool address
    void UnblockPoolAddress(const std::string& address);
    
    /// @brief Load pool blacklist
    [[nodiscard]] bool LoadPoolBlacklist(const std::filesystem::path& path);
    
    /// @brief Add pool to blacklist
    void AddToBlacklist(const PoolEndpointInfo& pool);
    
    /// @brief Check if pool is blacklisted
    [[nodiscard]] bool IsBlacklisted(const std::string& address) const;
    
    void RegisterConnectionCallback(PoolConnectionCallback callback);
    void RegisterStratumDetectedCallback(StratumDetectedCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();
    
    [[nodiscard]] PoolDetectorStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<PoolDetectionResult> GetRecentDetections(size_t maxCount = 100) const;
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PoolConnectionDetector();
    ~PoolConnectionDetector();
    
    std::unique_ptr<PoolConnectionDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetPoolProtocolTypeName(PoolProtocolType type) noexcept;
[[nodiscard]] std::string_view GetPoolStatusName(PoolStatus status) noexcept;
[[nodiscard]] std::string_view GetConnectionStateName(ConnectionState state) noexcept;
[[nodiscard]] std::string_view GetStratumCommandName(StratumCommand cmd) noexcept;
[[nodiscard]] std::string_view GetMinedCryptocurrencyName(MinedCryptocurrency crypto) noexcept;
[[nodiscard]] bool IsStratumPort(uint16_t port) noexcept;
[[nodiscard]] bool ValidateWalletAddress(std::string_view address, MinedCryptocurrency crypto);

}  // namespace CryptoMiners
}  // namespace ShadowStrike

#define SS_IS_STRATUM_TRAFFIC(payload) \
    ::ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance().IsStratumTraffic(payload)

#define SS_IS_MINING_POOL(ip, port) \
    ::ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance().IsPoolEndpoint(ip, port)