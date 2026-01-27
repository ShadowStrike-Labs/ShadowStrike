/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - CRYPTO MINER DETECTOR
 * ============================================================================
 *
 * @file CryptoMinerDetector.hpp
 * @brief Enterprise-grade cryptocurrency mining detection engine for identifying
 *        unauthorized CPU, GPU, and browser-based mining operations.
 *
 * This module provides comprehensive detection of cryptojacking attacks and
 * unauthorized cryptocurrency mining including XMRig, CGMiner, PhoenixMiner,
 * browser-based miners (Coinhive variants), and botnet mining components.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. CPU MINING DETECTION
 *    - Sustained high CPU usage
 *    - Mining algorithm patterns (CryptoNight, RandomX)
 *    - CPU affinity manipulation
 *    - Process priority anomalies
 *    - Thread pool patterns
 *
 * 2. GPU MINING DETECTION
 *    - CUDA/OpenCL usage monitoring
 *    - GPU memory allocation patterns
 *    - Compute shader analysis
 *    - Power consumption anomalies
 *    - Temperature spikes
 *
 * 3. BROWSER MINING DETECTION
 *    - WebAssembly (WASM) miner detection
 *    - JavaScript miner patterns
 *    - Web Worker abuse
 *    - Coinhive/CryptoLoot variants
 *    - Hidden iframe mining
 *
 * 4. NETWORK DETECTION
 *    - Stratum protocol identification
 *    - Mining pool connections
 *    - Wallet address extraction
 *    - Pool IP/domain blacklist
 *    - Traffic pattern analysis
 *
 * 5. SIGNATURE DETECTION
 *    - Known miner executables
 *    - In-memory signatures
 *    - Configuration patterns
 *    - Import table analysis
 *    - String patterns
 *
 * 6. BEHAVIORAL ANALYSIS
 *    - Resource usage patterns
 *    - Process genealogy
 *    - Persistence mechanisms
 *    - Evasion techniques
 *
 * KNOWN MINERS DETECTED:
 * ======================
 * - XMRig, XMR-Stak, XMRigCC
 * - CGMiner, BFGMiner
 * - PhoenixMiner, T-Rex, lolMiner
 * - Ethminer, Claymore
 * - NiceHash variants
 * - Coinhive, CryptoLoot, CoinIMP
 * - JSECoin, Crypto-Loot
 *
 * INTEGRATION:
 * ============
 * - Utils::ProcessUtils for process analysis
 * - Utils::NetworkUtils for network monitoring
 * - HashStore for known miner hashes
 * - PatternStore for mining patterns
 * - ThreatIntel for pool/wallet blacklists
 *
 * @note Requires elevated privileges for full GPU monitoring.
 * @note Browser mining detection requires browser integration.
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
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <filesystem>
#include <concepts>

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
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::CryptoMiners {
    class CryptoMinerDetectorImpl;
}

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace MinerConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // CPU THRESHOLDS
    // ========================================================================
    
    /// @brief Critical CPU usage threshold (%)
    inline constexpr double CPU_USAGE_CRITICAL = 95.0;
    
    /// @brief High CPU usage threshold (%)
    inline constexpr double CPU_USAGE_HIGH = 85.0;
    
    /// @brief Medium CPU usage threshold (%)
    inline constexpr double CPU_USAGE_MEDIUM = 60.0;
    
    /// @brief Sustained usage trigger duration (seconds)
    inline constexpr uint32_t SUSTAINED_USAGE_DURATION_SECS = 30;

    // ========================================================================
    // GPU THRESHOLDS
    // ========================================================================
    
    /// @brief GPU compute load threshold (%)
    inline constexpr double GPU_LOAD_THRESHOLD = 90.0;
    
    /// @brief GPU memory usage threshold (%)
    inline constexpr double GPU_MEMORY_THRESHOLD = 80.0;
    
    /// @brief GPU temperature warning (Celsius)
    inline constexpr double GPU_TEMP_WARNING = 75.0;
    
    /// @brief GPU temperature critical (Celsius)
    inline constexpr double GPU_TEMP_CRITICAL = 85.0;

    // ========================================================================
    // NETWORK
    // ========================================================================
    
    /// @brief Default stratum port
    inline constexpr uint16_t STRATUM_PORT_DEFAULT = 3333;
    
    /// @brief Alternative stratum ports
    inline constexpr uint16_t STRATUM_PORTS[] = {
        3333, 3334, 3335, 3336, 4444, 5555, 7777, 8888, 9999,
        14433, 14444, 45560, 45700
    };

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum processes to scan
    inline constexpr size_t MAX_PROCESS_SCAN = 1024;
    
    /// @brief Maximum pool addresses tracked
    inline constexpr size_t MAX_POOL_ADDRESSES = 4096;
    
    /// @brief Maximum wallet addresses tracked
    inline constexpr size_t MAX_WALLET_ADDRESSES = 1024;
    
    /// @brief Maximum detection history
    inline constexpr size_t MAX_DETECTION_HISTORY = 10000;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Resource monitoring interval (ms)
    inline constexpr uint32_t RESOURCE_MONITOR_INTERVAL_MS = 1000;
    
    /// @brief Network scan interval (ms)
    inline constexpr uint32_t NETWORK_SCAN_INTERVAL_MS = 5000;
    
    /// @brief Process scan interval (ms)
    inline constexpr uint32_t PROCESS_SCAN_INTERVAL_MS = 10000;

}  // namespace MinerConstants

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
 * @brief Miner type
 */
enum class MinerType : uint8_t {
    Unknown         = 0,
    CPUMiner        = 1,    ///< CPU-based miner (XMRig, etc.)
    GPUMiner        = 2,    ///< GPU-based miner (PhoenixMiner, etc.)
    BrowserMiner    = 3,    ///< JavaScript/WASM browser miner
    BotnetMiner     = 4,    ///< Integrated botnet miner
    CloudMiner      = 5,    ///< Cloud instance abuse
    HybridMiner     = 6     ///< CPU + GPU combined
};

/**
 * @brief Mining protocol
 */
enum class MiningProtocol : uint8_t {
    Unknown             = 0,
    Stratum             = 1,    ///< Stratum protocol
    StratumV2           = 2,    ///< Stratum v2
    GetBlockTemplate    = 3,    ///< getblocktemplate
    GetWork             = 4,    ///< getwork
    NiceHash            = 5,    ///< NiceHash stratum
    EthProxy            = 6,    ///< Ethereum proxy
    CryptoNight         = 7,    ///< CryptoNight protocol
    RandomX             = 8     ///< RandomX protocol
};

/**
 * @brief Mining algorithm
 */
enum class MiningAlgorithm : uint8_t {
    Unknown         = 0,
    SHA256          = 1,    ///< Bitcoin
    Scrypt          = 2,    ///< Litecoin
    Ethash          = 3,    ///< Ethereum (PoW)
    Etchash         = 4,    ///< Ethereum Classic
    CryptoNightR    = 5,    ///< Monero (old)
    RandomX         = 6,    ///< Monero (current)
    Kawpow          = 7,    ///< Ravencoin
    Autolykos       = 8,    ///< Ergo
    Equihash        = 9,    ///< Zcash
    CuckooCycle     = 10,   ///< Grin
    ProgPow         = 11    ///< ProgPow variants
};

/**
 * @brief Cryptocurrency being mined
 */
enum class Cryptocurrency : uint8_t {
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
 * @brief Detection source
 */
enum class DetectionSource : uint8_t {
    Unknown             = 0,
    CPUHeuristic        = 1,    ///< CPU usage pattern
    GPUHeuristic        = 2,    ///< GPU usage pattern
    NetworkStratum      = 3,    ///< Stratum protocol detection
    NetworkPoolIP       = 4,    ///< Known pool IP
    NetworkPoolDomain   = 5,    ///< Known pool domain
    SignatureBinary     = 6,    ///< Known miner hash
    SignatureMemory     = 7,    ///< In-memory pattern
    SignatureConfig     = 8,    ///< Config file pattern
    BrowserScript       = 9,    ///< JS/WASM analysis
    BrowserWASM         = 10,   ///< WebAssembly detection
    ProcessBehavior     = 11,   ///< Behavioral analysis
    ImportTable         = 12,   ///< Import analysis
    ThreatIntel         = 13    ///< Threat intel match
};

/**
 * @brief Known miner family
 */
enum class MinerFamily : uint16_t {
    Unknown             = 0,
    XMRig               = 1,
    XMRStak             = 2,
    CGMiner             = 3,
    BFGMiner            = 4,
    PhoenixMiner        = 5,
    TRexMiner           = 6,
    LolMiner            = 7,
    Ethminer            = 8,
    Claymore            = 9,
    NiceHash            = 10,
    NBMiner             = 11,
    TeamRedMiner        = 12,
    GMiner              = 13,
    Coinhive            = 100,
    CryptoLoot          = 101,
    CoinIMP             = 102,
    JSECoin             = 103,
    WebMinePool         = 104,
    Custom              = 255
};

/**
 * @brief Threat severity
 */
enum class ThreatSeverity : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4
};

/**
 * @brief Detection action
 */
enum class DetectionAction : uint8_t {
    None            = 0,
    Alert           = 1,
    Block           = 2,
    Terminate       = 3,
    Quarantine      = 4,
    BlockNetwork    = 5
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Resource usage stats
 */
struct ResourceUsageStats {
    /// @brief Overall CPU usage (%)
    double cpuUsagePercent = 0.0;
    
    /// @brief Per-core CPU usage
    std::vector<double> perCoreCpuUsage;
    
    /// @brief GPU usage (%)
    double gpuUsagePercent = 0.0;
    
    /// @brief GPU memory usage (%)
    double gpuMemoryPercent = 0.0;
    
    /// @brief GPU temperature (Celsius)
    double gpuTemperatureCelsius = 0.0;
    
    /// @brief GPU fan speed (RPM)
    uint32_t gpuFanSpeedRpm = 0;
    
    /// @brief GPU power draw (Watts)
    double gpuPowerDrawWatts = 0.0;
    
    /// @brief System memory usage (%)
    double memoryUsagePercent = 0.0;
    
    /// @brief Sample time
    SystemTimePoint sampleTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Network connection info
 */
struct MinerNetworkConnection {
    /// @brief Remote IP address
    std::string remoteIP;
    
    /// @brief Remote port
    uint16_t remotePort = 0;
    
    /// @brief Local port
    uint16_t localPort = 0;
    
    /// @brief Protocol detected
    MiningProtocol protocol = MiningProtocol::Unknown;
    
    /// @brief Pool address (full)
    std::string poolAddress;
    
    /// @brief Pool name (if known)
    std::string poolName;
    
    /// @brief Wallet address (if extracted)
    std::string walletAddress;
    
    /// @brief Worker name (if extracted)
    std::string workerName;
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Is encrypted (TLS)
    bool isEncrypted = false;
    
    /// @brief Connection time
    SystemTimePoint connectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Process miner info
 */
struct ProcessMinerInfo {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Parent PID
    uint32_t parentPid = 0;
    
    /// @brief File hash
    Hash256 fileHash{};
    
    /// @brief Is 64-bit
    bool is64Bit = false;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief CPU usage (%)
    double cpuUsage = 0.0;
    
    /// @brief Memory usage (bytes)
    uint64_t memoryUsage = 0;
    
    /// @brief Thread count
    uint32_t threadCount = 0;
    
    /// @brief Is signed
    bool isSigned = false;
    
    /// @brief Signer name
    std::wstring signerName;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Browser miner info
 */
struct BrowserMinerInfo {
    /// @brief Browser process ID
    uint32_t browserPid = 0;
    
    /// @brief Browser type
    std::string browserType;
    
    /// @brief Tab/frame URL
    std::string url;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Script source
    std::string scriptSource;
    
    /// @brief Is WebAssembly
    bool isWASM = false;
    
    /// @brief Is Web Worker
    bool isWebWorker = false;
    
    /// @brief CPU cores used
    uint32_t coresUsed = 0;
    
    /// @brief Throttle percent
    uint32_t throttlePercent = 0;
    
    /// @brief Miner library detected
    std::string minerLibrary;
    
    /// @brief Pool connection
    MinerNetworkConnection poolConnection;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Miner detection result
 */
struct MinerDetectionResult {
    /// @brief Detection ID
    std::string detectionId;
    
    /// @brief Is miner detected
    bool isMinerDetected = false;
    
    /// @brief Miner type
    MinerType minerType = MinerType::Unknown;
    
    /// @brief Miner family
    MinerFamily minerFamily = MinerFamily::Unknown;
    
    /// @brief Miner name (identified)
    std::string minerName;
    
    /// @brief Miner version (if known)
    std::string minerVersion;
    
    /// @brief Mining algorithm
    MiningAlgorithm algorithm = MiningAlgorithm::Unknown;
    
    /// @brief Cryptocurrency
    Cryptocurrency cryptocurrency = Cryptocurrency::Unknown;
    
    /// @brief Detection source
    DetectionSource source = DetectionSource::Unknown;
    
    /// @brief Additional sources
    std::vector<DetectionSource> additionalSources;
    
    /// @brief Threat severity
    ThreatSeverity severity = ThreatSeverity::None;
    
    /// @brief Confidence score (0-100)
    double confidenceScore = 0.0;
    
    /// @brief Threat score (0-100)
    double threatScore = 0.0;
    
    /// @brief Process info
    ProcessMinerInfo processInfo;
    
    /// @brief Browser info (if browser miner)
    std::optional<BrowserMinerInfo> browserInfo;
    
    /// @brief Network connections
    std::vector<MinerNetworkConnection> networkConnections;
    
    /// @brief Resource usage
    ResourceUsageStats resourceStats;
    
    /// @brief Pool addresses found
    std::vector<std::string> poolAddresses;
    
    /// @brief Wallet addresses found
    std::vector<std::string> walletAddresses;
    
    /// @brief Config file path (if found)
    std::wstring configFilePath;
    
    /// @brief Action taken
    DetectionAction actionTaken = DetectionAction::None;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Analysis duration
    std::chrono::milliseconds analysisDuration{0};
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Whitelist reason
    std::string whitelistReason;
    
    /// @brief MITRE ATT&CK techniques
    std::vector<std::string> mitreTechniques;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Mining pool info
 */
struct MiningPoolInfo {
    /// @brief Pool address/hostname
    std::string address;
    
    /// @brief Pool port
    uint16_t port = 0;
    
    /// @brief Pool name
    std::string name;
    
    /// @brief Supported algorithms
    std::vector<MiningAlgorithm> algorithms;
    
    /// @brief Supported cryptocurrencies
    std::vector<Cryptocurrency> cryptocurrencies;
    
    /// @brief Is known malicious
    bool isMalicious = false;
    
    /// @brief IP addresses
    std::vector<std::string> ipAddresses;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection statistics
 */
struct MinerDetectionStatistics {
    /// @brief Total scans performed
    std::atomic<uint64_t> totalScans{0};
    
    /// @brief Miners detected
    std::atomic<uint64_t> minersDetected{0};
    
    /// @brief CPU miners detected
    std::atomic<uint64_t> cpuMinersDetected{0};
    
    /// @brief GPU miners detected
    std::atomic<uint64_t> gpuMinersDetected{0};
    
    /// @brief Browser miners detected
    std::atomic<uint64_t> browserMinersDetected{0};
    
    /// @brief Miners terminated
    std::atomic<uint64_t> minersTerminated{0};
    
    /// @brief Pool connections blocked
    std::atomic<uint64_t> poolConnectionsBlocked{0};
    
    /// @brief Stratum connections detected
    std::atomic<uint64_t> stratumConnectionsDetected{0};
    
    /// @brief Whitelisted passes
    std::atomic<uint64_t> whitelistedPasses{0};
    
    /// @brief False positives reported
    std::atomic<uint64_t> falsePositives{0};
    
    /// @brief By miner family
    std::array<std::atomic<uint64_t>, 32> byFamily{};
    
    /// @brief By algorithm
    std::array<std::atomic<uint64_t>, 16> byAlgorithm{};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /// @brief Last detection time
    SystemTimePoint lastDetectionTime;
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct CryptoMinerDetectorConfiguration {
    /// @brief Enable CPU monitoring
    bool enableCPUMonitoring = true;
    
    /// @brief Enable GPU monitoring
    bool enableGPUMonitoring = true;
    
    /// @brief Enable network monitoring
    bool enableNetworkMonitoring = true;
    
    /// @brief Enable browser scanning
    bool enableBrowserScanning = true;
    
    /// @brief Enable signature scanning
    bool enableSignatureScanning = true;
    
    /// @brief Enable behavioral analysis
    bool enableBehavioralAnalysis = true;
    
    /// @brief CPU usage threshold
    double cpuUsageThreshold = MinerConstants::CPU_USAGE_HIGH;
    
    /// @brief GPU usage threshold
    double gpuUsageThreshold = MinerConstants::GPU_LOAD_THRESHOLD;
    
    /// @brief Sustained usage trigger (seconds)
    uint32_t sustainedUsageTriggerSecs = MinerConstants::SUSTAINED_USAGE_DURATION_SECS;
    
    /// @brief Block stratum protocol
    bool blockStratumProtocol = true;
    
    /// @brief Terminate miners on detection
    bool terminateOnDetection = false;
    
    /// @brief Alert on detection
    bool alertOnDetection = true;
    
    /// @brief Whitelisted applications
    std::vector<std::wstring> whitelistedApplications;
    
    /// @brief Whitelisted pool addresses (for legitimate mining)
    std::vector<std::string> whitelistedPools;
    
    /// @brief Custom pool blacklist path
    std::wstring poolBlacklistPath;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Detection callback
using MinerDetectedCallback = std::function<void(const MinerDetectionResult&)>;

/// @brief Resource callback
using ResourceAnomalyCallback = std::function<void(const ResourceUsageStats&)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// CRYPTO MINER DETECTOR CLASS
// ============================================================================

/**
 * @class CryptoMinerDetector
 * @brief Enterprise-grade cryptocurrency miner detection engine
 *
 * Provides comprehensive detection of unauthorized cryptocurrency mining
 * including CPU miners, GPU miners, and browser-based cryptojacking.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& detector = CryptoMinerDetector::Instance();
 *     detector.Initialize(config);
 *     
 *     // Scan specific process
 *     auto result = detector.ScanProcess(pid);
 *     if (result.isMinerDetected) {
 *         // Handle detection
 *     }
 * @endcode
 */
class CryptoMinerDetector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static CryptoMinerDetector& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    CryptoMinerDetector(const CryptoMinerDetector&) = delete;
    CryptoMinerDetector& operator=(const CryptoMinerDetector&) = delete;
    CryptoMinerDetector(CryptoMinerDetector&&) = delete;
    CryptoMinerDetector& operator=(CryptoMinerDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize detector
     */
    [[nodiscard]] bool Initialize(const CryptoMinerDetectorConfiguration& config = {});
    
    /**
     * @brief Shutdown detector
     */
    void Shutdown();
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    /**
     * @brief Check if running
     */
    [[nodiscard]] bool IsRunning() const noexcept;
    
    // ========================================================================
    // CONTROL
    // ========================================================================
    
    /**
     * @brief Start monitoring
     */
    [[nodiscard]] bool Start();
    
    /**
     * @brief Stop monitoring
     */
    [[nodiscard]] bool Stop();
    
    /**
     * @brief Pause monitoring
     */
    void Pause();
    
    /**
     * @brief Resume monitoring
     */
    void Resume();
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool UpdateConfiguration(const CryptoMinerDetectorConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] CryptoMinerDetectorConfiguration GetConfiguration() const;
    
    // ========================================================================
    // PROCESS SCANNING
    // ========================================================================
    
    /**
     * @brief Scan specific process
     */
    [[nodiscard]] MinerDetectionResult ScanProcess(uint32_t processId);
    
    /**
     * @brief Scan process by name
     */
    [[nodiscard]] MinerDetectionResult ScanProcessByName(std::wstring_view processName);
    
    /**
     * @brief Scan all processes
     */
    [[nodiscard]] std::vector<MinerDetectionResult> ScanAllProcesses();
    
    /**
     * @brief Quick scan (high CPU processes only)
     */
    [[nodiscard]] std::vector<MinerDetectionResult> QuickScan();
    
    // ========================================================================
    // BROWSER SCANNING
    // ========================================================================
    
    /**
     * @brief Scan browser for mining scripts
     */
    [[nodiscard]] std::vector<BrowserMinerInfo> ScanBrowsers();
    
    /**
     * @brief Scan script content
     */
    [[nodiscard]] bool ScanBrowserScript(const std::string& scriptContent);
    
    /**
     * @brief Scan WASM module
     */
    [[nodiscard]] bool ScanWASMModule(std::span<const uint8_t> wasmData);
    
    // ========================================================================
    // NETWORK ANALYSIS
    // ========================================================================
    
    /**
     * @brief Check if host is mining pool
     */
    [[nodiscard]] bool IsMiningPool(const std::string& host, uint16_t port = 0) const;
    
    /**
     * @brief Detect stratum protocol
     */
    [[nodiscard]] bool DetectStratumProtocol(std::span<const uint8_t> payload) const;
    
    /**
     * @brief Get active mining connections
     */
    [[nodiscard]] std::vector<MinerNetworkConnection> GetActiveMiningConnections() const;
    
    /**
     * @brief Block mining pool connection
     */
    [[nodiscard]] bool BlockPoolConnection(const std::string& poolAddress);
    
    // ========================================================================
    // RESOURCE MONITORING
    // ========================================================================
    
    /**
     * @brief Analyze system resources
     */
    void AnalyzeSystemResources();
    
    /**
     * @brief Get current resource usage
     */
    [[nodiscard]] ResourceUsageStats GetResourceUsage() const;
    
    /**
     * @brief Get process resource usage
     */
    [[nodiscard]] ResourceUsageStats GetProcessResourceUsage(uint32_t processId) const;
    
    // ========================================================================
    // POOL DATABASE
    // ========================================================================
    
    /**
     * @brief Load pool blacklist
     */
    [[nodiscard]] bool LoadPoolBlacklist(const std::filesystem::path& path);
    
    /**
     * @brief Add pool to blacklist
     */
    void AddPoolToBlacklist(const MiningPoolInfo& pool);
    
    /**
     * @brief Get pool info
     */
    [[nodiscard]] std::optional<MiningPoolInfo> GetPoolInfo(const std::string& address) const;
    
    // ========================================================================
    // REMEDIATION
    // ========================================================================
    
    /**
     * @brief Terminate miner process
     */
    [[nodiscard]] bool TerminateMiner(uint32_t processId);
    
    /**
     * @brief Quarantine miner
     */
    [[nodiscard]] bool QuarantineMiner(uint32_t processId);
    
    /**
     * @brief Block miner network
     */
    [[nodiscard]] bool BlockMinerNetwork(uint32_t processId);
    
    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    /**
     * @brief Check if process is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;
    
    /**
     * @brief Add to whitelist
     */
    void AddToWhitelist(uint32_t processId, const std::string& reason);
    
    /**
     * @brief Add path to whitelist
     */
    void AddPathToWhitelist(const std::filesystem::path& path, const std::string& reason);
    
    /**
     * @brief Remove from whitelist
     */
    void RemoveFromWhitelist(uint32_t processId);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register detection callback
     */
    void RegisterDetectionCallback(MinerDetectedCallback callback);
    
    /**
     * @brief Register resource anomaly callback
     */
    void RegisterResourceAnomalyCallback(ResourceAnomalyCallback callback);
    
    /**
     * @brief Register error callback
     */
    void RegisterErrorCallback(ErrorCallback callback);
    
    /**
     * @brief Unregister callbacks
     */
    void UnregisterCallbacks();
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] MinerDetectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get recent detections
     */
    [[nodiscard]] std::vector<MinerDetectionResult> GetRecentDetections(
        size_t maxCount = 100) const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    CryptoMinerDetector();
    ~CryptoMinerDetector();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<CryptoMinerDetectorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get miner type name
 */
[[nodiscard]] std::string_view GetMinerTypeName(MinerType type) noexcept;

/**
 * @brief Get mining protocol name
 */
[[nodiscard]] std::string_view GetMiningProtocolName(MiningProtocol protocol) noexcept;

/**
 * @brief Get mining algorithm name
 */
[[nodiscard]] std::string_view GetMiningAlgorithmName(MiningAlgorithm algorithm) noexcept;

/**
 * @brief Get cryptocurrency name
 */
[[nodiscard]] std::string_view GetCryptocurrencyName(Cryptocurrency crypto) noexcept;

/**
 * @brief Get detection source name
 */
[[nodiscard]] std::string_view GetDetectionSourceName(DetectionSource source) noexcept;

/**
 * @brief Get miner family name
 */
[[nodiscard]] std::string_view GetMinerFamilyName(MinerFamily family) noexcept;

/**
 * @brief Check if port is common mining port
 */
[[nodiscard]] bool IsMiningPort(uint16_t port) noexcept;

/**
 * @brief Validate wallet address format
 */
[[nodiscard]] bool ValidateWalletAddress(std::string_view address, Cryptocurrency crypto);

}  // namespace CryptoMiners
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Scan process for mining
 */
#define SS_SCAN_MINER(pid) \
    ::ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance().ScanProcess(pid)

/**
 * @brief Check if host is mining pool
 */
#define SS_IS_MINING_POOL(host, port) \
    ::ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance().IsMiningPool(host, port)