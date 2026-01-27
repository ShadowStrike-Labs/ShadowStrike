/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - BROWSER MINER DETECTOR
 * ============================================================================
 *
 * @file BrowserMinerDetector.hpp
 * @brief Enterprise-grade detection engine for in-browser cryptojacking attacks
 *        including JavaScript miners, WebAssembly miners, and Web Worker abuse.
 *
 * Provides comprehensive detection of browser-based cryptocurrency mining
 * scripts that hijack user CPU resources for unauthorized mining operations.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. JAVASCRIPT ANALYSIS
 *    - Mining library detection
 *    - Obfuscation pattern recognition
 *    - String signature matching
 *    - API usage analysis
 *    - Control flow patterns
 *
 * 2. WEBASSEMBLY ANALYSIS
 *    - WASM binary inspection
 *    - Mining algorithm detection
 *    - Cryptographic instruction patterns
 *    - Memory access patterns
 *    - Loop structure analysis
 *
 * 3. WEB WORKER DETECTION
 *    - Worker thread monitoring
 *    - CPU usage per worker
 *    - Worker script analysis
 *    - SharedArrayBuffer abuse
 *    - Dedicated vs shared workers
 *
 * 4. NETWORK ANALYSIS
 *    - WebSocket connections
 *    - Mining pool endpoints
 *    - Stratum over WS
 *    - XHR/Fetch to pools
 *    - CORS bypasses
 *
 * 5. BEHAVIORAL ANALYSIS
 *    - Tab CPU consumption
 *    - Mining throttle patterns
 *    - User interaction correlation
 *    - Background tab behavior
 *    - Persistent mining
 *
 * 6. KNOWN MINER FAMILIES
 *    - Coinhive (historic)
 *    - CryptoLoot
 *    - CoinIMP
 *    - JSECoin
 *    - WebMinePool
 *    - Authedmine
 *    - DeepMiner
 *
 * INTEGRATION:
 * ============
 * - CPUUsageAnalyzer for resource correlation
 * - PatternStore for mining signatures
 * - ThreatIntel for domain blacklists
 *
 * @note Requires browser hook or extension for script interception.
 * @note WebAssembly analysis requires WASM parsing capability.
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
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::CryptoMiners {
    class BrowserMinerDetectorImpl;
}

namespace ShadowStrike {
namespace CryptoMiners {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace BrowserMinerConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum script size to scan (bytes)
    inline constexpr size_t MAX_SCRIPT_SCAN_SIZE = 10 * 1024 * 1024;  // 10MB
    
    /// @brief Maximum WASM module size (bytes)
    inline constexpr size_t MAX_WASM_SIZE = 50 * 1024 * 1024;  // 50MB
    
    /// @brief Maximum workers to track per tab
    inline constexpr size_t MAX_WORKERS_PER_TAB = 32;
    
    /// @brief Maximum tabs to monitor
    inline constexpr size_t MAX_MONITORED_TABS = 256;
    
    /// @brief Maximum blocked domains
    inline constexpr size_t MAX_BLOCKED_DOMAINS = 8192;

    // ========================================================================
    // THRESHOLDS
    // ========================================================================
    
    /// @brief Tab CPU threshold for mining suspicion (%)
    inline constexpr double TAB_CPU_THRESHOLD = 50.0;
    
    /// @brief Worker CPU threshold (%)
    inline constexpr double WORKER_CPU_THRESHOLD = 30.0;
    
    /// @brief Confidence threshold for detection
    inline constexpr double CONFIDENCE_THRESHOLD = 0.7;
    
    /// @brief Sustained CPU duration for flag (seconds)
    inline constexpr uint32_t SUSTAINED_CPU_SECS = 10;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Tab monitor interval (ms)
    inline constexpr uint32_t TAB_MONITOR_INTERVAL_MS = 500;
    
    /// @brief Worker scan interval (ms)
    inline constexpr uint32_t WORKER_SCAN_INTERVAL_MS = 1000;

}  // namespace BrowserMinerConstants

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
 * @brief Script type
 */
enum class ScriptType : uint8_t {
    Unknown         = 0,
    JavaScript      = 1,    ///< Plain JavaScript
    MinifiedJS      = 2,    ///< Minified JavaScript
    ObfuscatedJS    = 3,    ///< Obfuscated JavaScript
    WebAssembly     = 4,    ///< WASM binary
    AsmJS           = 5,    ///< asm.js module
    TypeScript      = 6     ///< TypeScript (compiled)
};

/**
 * @brief Browser miner family
 */
enum class BrowserMinerFamily : uint8_t {
    Unknown         = 0,
    Coinhive        = 1,    ///< Coinhive (defunct but variants exist)
    CryptoLoot      = 2,    ///< CryptoLoot
    CoinIMP         = 3,    ///< CoinIMP
    JSECoin         = 4,    ///< JSECoin
    WebMinePool     = 5,    ///< WebMinePool
    Authedmine      = 6,    ///< Authedmine
    DeepMiner       = 7,    ///< DeepMiner
    MineMyTraffic   = 8,    ///< MineMyTraffic
    PPoi            = 9,    ///< PPoi miner
    GenericWASM     = 10,   ///< Generic WASM miner
    GenericJS       = 11,   ///< Generic JS miner
    Custom          = 255   ///< Custom/unknown variant
};

/**
 * @brief Mining algorithm detected
 */
enum class BrowserMiningAlgorithm : uint8_t {
    Unknown         = 0,
    CryptoNight     = 1,    ///< Monero (old)
    RandomX         = 2,    ///< Monero (current)
    CryptoNightR    = 3,    ///< CryptoNight variant
    CryptoNightV7   = 4,    ///< CryptoNight v7
    CryptoNightLite = 5,    ///< CryptoNight Lite
    Argon2          = 6     ///< Argon2 based
};

/**
 * @brief Detection method
 */
enum class BrowserDetectionMethod : uint8_t {
    Unknown             = 0,
    SignatureMatch      = 1,    ///< Known signature
    StringPattern       = 2,    ///< String pattern match
    WASMAnalysis        = 3,    ///< WASM instruction analysis
    BehavioralCPU       = 4,    ///< CPU usage behavior
    NetworkPool         = 5,    ///< Pool connection detected
    WorkerAbuse         = 6,    ///< Web Worker abuse
    DomainBlacklist     = 7,    ///< Blocked domain
    HeuristicAnalysis   = 8,    ///< Heuristic detection
    ThreatIntel         = 9     ///< Threat intel match
};

/**
 * @brief Worker type
 */
enum class WebWorkerType : uint8_t {
    Unknown         = 0,
    Dedicated       = 1,    ///< Dedicated worker
    Shared          = 2,    ///< Shared worker
    Service         = 3     ///< Service worker
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
 * @brief Browser script info
 */
struct BrowserScriptInfo {
    /// @brief Browser process ID
    uint32_t browserPid = 0;
    
    /// @brief Tab ID (browser-specific)
    uint64_t tabId = 0;
    
    /// @brief Frame ID
    uint64_t frameId = 0;
    
    /// @brief Source URL
    std::string sourceUrl;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Script type
    ScriptType scriptType = ScriptType::Unknown;
    
    /// @brief Script size (bytes)
    size_t scriptSize = 0;
    
    /// @brief Script hash
    Hash256 scriptHash{};
    
    /// @brief Is inline script
    bool isInline = false;
    
    /// @brief Is from extension
    bool isFromExtension = false;
    
    /// @brief Script content (truncated for large scripts)
    std::string contentPreview;
    
    /// @brief Load time
    SystemTimePoint loadTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Web worker info
 */
struct WebWorkerInfo {
    /// @brief Worker ID
    uint64_t workerId = 0;
    
    /// @brief Parent tab ID
    uint64_t parentTabId = 0;
    
    /// @brief Worker type
    WebWorkerType workerType = WebWorkerType::Unknown;
    
    /// @brief Worker script URL
    std::string scriptUrl;
    
    /// @brief Worker name
    std::string workerName;
    
    /// @brief CPU usage (%)
    double cpuUsage = 0.0;
    
    /// @brief Memory usage (bytes)
    uint64_t memoryUsage = 0;
    
    /// @brief Is mining suspected
    bool isMiningSpected = false;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief WASM analysis result
 */
struct WASMAnalysisResult {
    /// @brief Is valid WASM
    bool isValidWASM = false;
    
    /// @brief Module size (bytes)
    size_t moduleSize = 0;
    
    /// @brief Is mining module
    bool isMiningModule = false;
    
    /// @brief Detected algorithm
    BrowserMiningAlgorithm algorithm = BrowserMiningAlgorithm::Unknown;
    
    /// @brief Has crypto instructions
    bool hasCryptoInstructions = false;
    
    /// @brief Has large memory
    bool hasLargeMemory = false;
    
    /// @brief Memory pages requested
    uint32_t memoryPages = 0;
    
    /// @brief Function count
    uint32_t functionCount = 0;
    
    /// @brief Loop density score
    double loopDensityScore = 0.0;
    
    /// @brief Confidence score
    double confidenceScore = 0.0;
    
    /// @brief Suspicious patterns found
    std::vector<std::string> suspiciousPatterns;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection result
 */
struct BrowserMinerDetectionResult {
    /// @brief Detection ID
    std::string detectionId;
    
    /// @brief Is miner detected
    bool isMinerDetected = false;
    
    /// @brief Miner family
    BrowserMinerFamily minerFamily = BrowserMinerFamily::Unknown;
    
    /// @brief Family name
    std::string familyName;
    
    /// @brief Mining algorithm
    BrowserMiningAlgorithm algorithm = BrowserMiningAlgorithm::Unknown;
    
    /// @brief Detection method
    BrowserDetectionMethod detectionMethod = BrowserDetectionMethod::Unknown;
    
    /// @brief Additional methods
    std::vector<BrowserDetectionMethod> additionalMethods;
    
    /// @brief Threat severity
    ThreatSeverity severity = ThreatSeverity::None;
    
    /// @brief Confidence score (0-100)
    double confidenceScore = 0.0;
    
    /// @brief Script info
    BrowserScriptInfo scriptInfo;
    
    /// @brief WASM analysis (if applicable)
    std::optional<WASMAnalysisResult> wasmAnalysis;
    
    /// @brief Related workers
    std::vector<WebWorkerInfo> relatedWorkers;
    
    /// @brief Pool addresses found
    std::vector<std::string> poolAddresses;
    
    /// @brief Wallet address (if extracted)
    std::string walletAddress;
    
    /// @brief Mining throttle (if detected)
    std::optional<uint32_t> throttlePercent;
    
    /// @brief Evidence details
    std::string evidence;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Analysis duration
    std::chrono::milliseconds analysisDuration{0};
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Tab mining info
 */
struct TabMiningInfo {
    /// @brief Tab ID
    uint64_t tabId = 0;
    
    /// @brief Browser PID
    uint32_t browserPid = 0;
    
    /// @brief Tab URL
    std::string url;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Is mining
    bool isMining = false;
    
    /// @brief Current CPU usage (%)
    double cpuUsage = 0.0;
    
    /// @brief Average CPU usage (%)
    double avgCpuUsage = 0.0;
    
    /// @brief Peak CPU usage (%)
    double peakCpuUsage = 0.0;
    
    /// @brief High CPU duration (seconds)
    uint32_t highCpuDurationSecs = 0;
    
    /// @brief Worker count
    uint32_t workerCount = 0;
    
    /// @brief Has WASM
    bool hasWASM = false;
    
    /// @brief Is background tab
    bool isBackgroundTab = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection statistics
 */
struct BrowserMinerStatistics {
    /// @brief Scripts scanned
    std::atomic<uint64_t> scriptsScanned{0};
    
    /// @brief WASM modules scanned
    std::atomic<uint64_t> wasmModulesScanned{0};
    
    /// @brief Miners detected
    std::atomic<uint64_t> minersDetected{0};
    
    /// @brief Miners blocked
    std::atomic<uint64_t> minersBlocked{0};
    
    /// @brief Domains blocked
    std::atomic<uint64_t> domainsBlocked{0};
    
    /// @brief Workers terminated
    std::atomic<uint64_t> workersTerminated{0};
    
    /// @brief Tabs flagged
    std::atomic<uint64_t> tabsFlagged{0};
    
    /// @brief By miner family
    std::array<std::atomic<uint64_t>, 16> byFamily{};
    
    /// @brief By detection method
    std::array<std::atomic<uint64_t>, 16> byMethod{};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
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
struct BrowserMinerDetectorConfiguration {
    /// @brief Enable JavaScript scanning
    bool enableJSScanning = true;
    
    /// @brief Enable WASM scanning
    bool enableWASMScanning = true;
    
    /// @brief Enable heuristic analysis
    bool enableHeuristics = true;
    
    /// @brief Enable worker monitoring
    bool enableWorkerMonitoring = true;
    
    /// @brief Enable domain blocking
    bool enableDomainBlocking = true;
    
    /// @brief Block known mining domains
    bool blockKnownDomains = true;
    
    /// @brief Maximum script size to scan
    size_t maxScriptScanSize = BrowserMinerConstants::MAX_SCRIPT_SCAN_SIZE;
    
    /// @brief Maximum WASM size to scan
    size_t maxWASMSize = BrowserMinerConstants::MAX_WASM_SIZE;
    
    /// @brief Tab CPU threshold
    double tabCpuThreshold = BrowserMinerConstants::TAB_CPU_THRESHOLD;
    
    /// @brief Confidence threshold
    double confidenceThreshold = BrowserMinerConstants::CONFIDENCE_THRESHOLD;
    
    /// @brief Terminate mining workers
    bool terminateMiningWorkers = true;
    
    /// @brief Custom domain blacklist path
    std::wstring domainBlacklistPath;
    
    /// @brief Whitelisted domains
    std::vector<std::string> whitelistedDomains;
    
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
using MinerFoundCallback = std::function<void(const BrowserMinerDetectionResult&, const BrowserScriptInfo&)>;

/// @brief Tab mining callback
using TabMiningCallback = std::function<void(const TabMiningInfo&)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// BROWSER MINER DETECTOR CLASS
// ============================================================================

/**
 * @class BrowserMinerDetector
 * @brief Enterprise-grade browser cryptojacking detection engine
 *
 * Provides comprehensive detection of in-browser cryptocurrency mining
 * including JavaScript miners, WASM miners, and Web Worker abuse.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& detector = BrowserMinerDetector::Instance();
 *     detector.Initialize(config);
 *     
 *     // Analyze script
 *     auto result = detector.AnalyzeScript(scriptContent);
 *     if (result.isMinerDetected) {
 *         // Handle detection
 *     }
 * @endcode
 */
class BrowserMinerDetector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static BrowserMinerDetector& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    BrowserMinerDetector(const BrowserMinerDetector&) = delete;
    BrowserMinerDetector& operator=(const BrowserMinerDetector&) = delete;
    BrowserMinerDetector(BrowserMinerDetector&&) = delete;
    BrowserMinerDetector& operator=(BrowserMinerDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize detector
     */
    [[nodiscard]] bool Initialize(const BrowserMinerDetectorConfiguration& config = {});
    
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
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool UpdateConfiguration(const BrowserMinerDetectorConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] BrowserMinerDetectorConfiguration GetConfiguration() const;
    
    // ========================================================================
    // SCRIPT ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze JavaScript source
     */
    [[nodiscard]] BrowserMinerDetectionResult AnalyzeScript(const std::string& scriptSource);
    
    /**
     * @brief Analyze script with info
     */
    [[nodiscard]] BrowserMinerDetectionResult AnalyzeScript(
        const std::string& scriptSource,
        const BrowserScriptInfo& scriptInfo);
    
    /**
     * @brief Analyze WebAssembly binary
     */
    [[nodiscard]] BrowserMinerDetectionResult AnalyzeWASM(std::span<const uint8_t> wasmBinary);
    
    /**
     * @brief Analyze WASM with info
     */
    [[nodiscard]] BrowserMinerDetectionResult AnalyzeWASM(
        std::span<const uint8_t> wasmBinary,
        const BrowserScriptInfo& scriptInfo);
    
    /**
     * @brief Quick signature check
     */
    [[nodiscard]] bool QuickSignatureCheck(const std::string& content) const;
    
    // ========================================================================
    // TAB MONITORING
    // ========================================================================
    
    /**
     * @brief Check if tab is mining
     */
    [[nodiscard]] bool IsTabMining(uint32_t browserPid, uint64_t tabId);
    
    /**
     * @brief Get tab mining info
     */
    [[nodiscard]] std::optional<TabMiningInfo> GetTabMiningInfo(
        uint32_t browserPid, uint64_t tabId) const;
    
    /**
     * @brief Get all mining tabs
     */
    [[nodiscard]] std::vector<TabMiningInfo> GetMiningTabs() const;
    
    /**
     * @brief Start monitoring tab
     */
    void StartTabMonitoring(uint32_t browserPid, uint64_t tabId);
    
    /**
     * @brief Stop monitoring tab
     */
    void StopTabMonitoring(uint32_t browserPid, uint64_t tabId);
    
    // ========================================================================
    // WORKER MONITORING
    // ========================================================================
    
    /**
     * @brief Get workers for tab
     */
    [[nodiscard]] std::vector<WebWorkerInfo> GetWorkers(
        uint32_t browserPid, uint64_t tabId) const;
    
    /**
     * @brief Terminate mining workers
     */
    [[nodiscard]] size_t TerminateMiningWorkers(uint32_t browserPid, uint64_t tabId);
    
    // ========================================================================
    // DOMAIN MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Check if domain is blocked
     */
    [[nodiscard]] bool IsDomainBlocked(const std::string& domain) const;
    
    /**
     * @brief Block domain
     */
    void BlockDomain(const std::string& domain);
    
    /**
     * @brief Unblock domain
     */
    void UnblockDomain(const std::string& domain);
    
    /**
     * @brief Load domain blacklist
     */
    [[nodiscard]] bool LoadDomainBlacklist(const std::filesystem::path& path);
    
    /**
     * @brief Get blocked domain count
     */
    [[nodiscard]] size_t GetBlockedDomainCount() const noexcept;
    
    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    /**
     * @brief Add domain to whitelist
     */
    void WhitelistDomain(const std::string& domain, const std::string& reason);
    
    /**
     * @brief Check if domain is whitelisted
     */
    [[nodiscard]] bool IsDomainWhitelisted(const std::string& domain) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register miner found callback
     */
    void RegisterMinerFoundCallback(MinerFoundCallback callback);
    
    /**
     * @brief Register tab mining callback
     */
    void RegisterTabMiningCallback(TabMiningCallback callback);
    
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
    [[nodiscard]] BrowserMinerStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get recent detections
     */
    [[nodiscard]] std::vector<BrowserMinerDetectionResult> GetRecentDetections(
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
    
    BrowserMinerDetector();
    ~BrowserMinerDetector();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<BrowserMinerDetectorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get script type name
 */
[[nodiscard]] std::string_view GetScriptTypeName(ScriptType type) noexcept;

/**
 * @brief Get browser miner family name
 */
[[nodiscard]] std::string_view GetBrowserMinerFamilyName(BrowserMinerFamily family) noexcept;

/**
 * @brief Get browser mining algorithm name
 */
[[nodiscard]] std::string_view GetBrowserMiningAlgorithmName(BrowserMiningAlgorithm algo) noexcept;

/**
 * @brief Get browser detection method name
 */
[[nodiscard]] std::string_view GetBrowserDetectionMethodName(BrowserDetectionMethod method) noexcept;

/**
 * @brief Get web worker type name
 */
[[nodiscard]] std::string_view GetWebWorkerTypeName(WebWorkerType type) noexcept;

/**
 * @brief Check if URL is known mining domain
 */
[[nodiscard]] bool IsKnownMiningDomain(std::string_view domain);

/**
 * @brief Extract domain from URL
 */
[[nodiscard]] std::string ExtractDomain(std::string_view url);

}  // namespace CryptoMiners
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Analyze browser script for mining
 */
#define SS_ANALYZE_BROWSER_SCRIPT(script) \
    ::ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance().AnalyzeScript(script)

/**
 * @brief Check if tab is mining
 */
#define SS_IS_TAB_MINING(pid, tabId) \
    ::ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance().IsTabMining(pid, tabId)