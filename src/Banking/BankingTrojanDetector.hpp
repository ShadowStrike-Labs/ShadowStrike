/**
 * ============================================================================
 * ShadowStrike Banking Protection - BANKING TROJAN DETECTOR
 * ============================================================================
 *
 * @file BankingTrojanDetector.hpp
 * @brief Enterprise-grade banking trojan detection engine for identifying and
 *        neutralizing sophisticated financial malware threats.
 *
 * This module provides comprehensive detection capabilities for banking trojans
 * including Zeus, Emotet, TrickBot, Dridex, QakBot, Gozi, and emerging variants.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. PROCESS ANALYSIS
 *    - Suspicious process injection
 *    - Code hollowing detection
 *    - Memory anomaly scanning
 *    - Import table tampering
 *    - Thread hijacking
 *
 * 2. API HOOKING DETECTION
 *    - User-mode API hooks
 *    - Browser function hooks
 *    - Network API interception
 *    - Crypto API monitoring
 *    - SSL/TLS tampering
 *
 * 3. WEB INJECTION DETECTION
 *    - Form grabbing patterns
 *    - HTML/JS injection
 *    - Man-in-Browser attacks
 *    - DOM manipulation
 *    - Credential theft vectors
 *
 * 4. NETWORK ANALYSIS
 *    - C2 communication patterns
 *    - DGA domain detection
 *    - Exfiltration attempts
 *    - Proxy/SOCKS tunneling
 *    - TOR/I2P detection
 *
 * 5. BEHAVIORAL ANALYSIS
 *    - Keylogging patterns
 *    - Screenshot capture
 *    - Clipboard monitoring
 *    - Browser targeting
 *    - Persistence mechanisms
 *
 * 6. FAMILY IDENTIFICATION
 *    - Zeus/Zbot variants
 *    - Emotet/Heodo
 *    - TrickBot
 *    - Dridex/Cridex
 *    - QakBot/Qbot
 *    - Gozi/Ursnif/ISFB
 *    - IcedID/BokBot
 *
 * INTEGRATION:
 * ============
 * - Utils::ProcessUtils for process analysis
 * - Utils::NetworkUtils for C2 detection
 * - HashStore for known sample matching
 * - PatternStore for behavioral patterns
 * - ThreatIntel for real-time IOC lookup
 *
 * @note Requires elevated privileges for full detection capabilities.
 * @note Integrates with browser protection for web inject detection.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: PCI-DSS 4.0, SOC2, ISO 27001
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
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Banking {
    class BankingTrojanDetectorImpl;
}

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace BankingTrojanConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // DETECTION LIMITS
    // ========================================================================
    
    /// @brief Maximum processes to scan
    inline constexpr size_t MAX_PROCESS_SCAN_COUNT = 4096;
    
    /// @brief Maximum injection targets per process
    inline constexpr size_t MAX_INJECTION_TARGETS = 512;
    
    /// @brief Maximum hooked functions to track
    inline constexpr size_t MAX_HOOKED_FUNCTIONS = 1024;
    
    /// @brief Maximum memory regions to scan
    inline constexpr size_t MAX_MEMORY_REGIONS = 8192;
    
    /// @brief Maximum web injections to track
    inline constexpr size_t MAX_WEB_INJECTIONS = 256;
    
    /// @brief Maximum C2 servers to track
    inline constexpr size_t MAX_C2_SERVERS = 256;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Real-time scan interval (milliseconds)
    inline constexpr uint32_t REAL_TIME_SCAN_INTERVAL_MS = 500;
    
    /// @brief Memory scan interval (seconds)
    inline constexpr uint32_t MEMORY_SCAN_INTERVAL_SECS = 30;
    
    /// @brief Network monitor interval (milliseconds)
    inline constexpr uint32_t NETWORK_MONITOR_INTERVAL_MS = 100;
    
    /// @brief Behavioral analysis window (seconds)
    inline constexpr uint32_t BEHAVIORAL_WINDOW_SECS = 60;

    // ========================================================================
    // THRESHOLDS
    // ========================================================================
    
    /// @brief Minimum threat score for low severity
    inline constexpr double THREAT_SCORE_LOW = 30.0;
    
    /// @brief Minimum threat score for medium severity
    inline constexpr double THREAT_SCORE_MEDIUM = 50.0;
    
    /// @brief Minimum threat score for high severity
    inline constexpr double THREAT_SCORE_HIGH = 75.0;
    
    /// @brief Minimum threat score for critical severity
    inline constexpr double THREAT_SCORE_CRITICAL = 90.0;
    
    /// @brief Minimum confidence for detection
    inline constexpr double MIN_CONFIDENCE = 0.6;
    
    /// @brief ML detection threshold
    inline constexpr double ML_THRESHOLD = 0.75;

    // ========================================================================
    // BROWSER TARGETS
    // ========================================================================
    
    /// @brief Browser process names targeted by banking trojans
    inline constexpr const wchar_t* TARGET_BROWSERS[] = {
        L"chrome.exe", L"firefox.exe", L"msedge.exe", L"iexplore.exe",
        L"opera.exe", L"brave.exe", L"vivaldi.exe"
    };

}  // namespace BankingTrojanConstants

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
 * @brief Banking trojan family
 */
enum class TrojanFamily : uint16_t {
    Unknown             = 0,
    Zeus                = 1,    ///< Zeus/Zbot
    ZeusGameover        = 2,    ///< Gameover Zeus
    Emotet              = 3,    ///< Emotet/Heodo
    TrickBot            = 4,    ///< TrickBot
    Dridex              = 5,    ///< Dridex/Cridex
    QakBot              = 6,    ///< QakBot/Qbot/Pinkslipbot
    Gozi                = 7,    ///< Gozi/Ursnif/ISFB
    IcedID              = 8,    ///< IcedID/BokBot
    Carberp             = 9,    ///< Carberp
    SpyEye              = 10,   ///< SpyEye
    Citadel             = 11,   ///< Citadel
    Kronos              = 12,   ///< Kronos/Osiris
    Ramnit              = 13,   ///< Ramnit
    Vawtrak             = 14,   ///< Vawtrak/Neverquest
    Tinba               = 15,   ///< Tinba/TinyBanker
    Panda               = 16,   ///< Panda Banker
    BankBot             = 17,   ///< BankBot (Android)
    Custom              = 0xFFFF
};

/**
 * @brief Detection method
 */
enum class DetectionMethod : uint16_t {
    Unknown             = 0,
    SignatureMatch      = 1,    ///< Hash/signature match
    HeuristicAnalysis   = 2,    ///< Heuristic detection
    BehavioralAnalysis  = 3,    ///< Behavioral patterns
    MemoryScanning      = 4,    ///< Memory analysis
    APIHookDetection    = 5,    ///< API hook detection
    WebInjectDetection  = 6,    ///< Web injection detection
    NetworkAnalysis     = 7,    ///< Network traffic analysis
    MachineLearning     = 8,    ///< ML-based detection
    ThreatIntelMatch    = 9,    ///< Threat intel IOC match
    YaraRuleMatch       = 10    ///< YARA rule match
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
 * @brief Hook type
 */
enum class HookType : uint8_t {
    Unknown         = 0,
    InlineHook      = 1,    ///< JMP/CALL patch
    IATHook         = 2,    ///< Import Address Table
    EATHook         = 3,    ///< Export Address Table
    VTableHook      = 4,    ///< Virtual function table
    DebugHook       = 5,    ///< Debug register
    PageGuardHook   = 6     ///< PAGE_GUARD exception
};

/**
 * @brief Injection technique
 */
enum class InjectionTechnique : uint8_t {
    Unknown             = 0,
    DLLInjection        = 1,    ///< Classic DLL injection
    ProcessHollowing    = 2,    ///< Process hollowing
    AtomBombing         = 3,    ///< Atom bombing
    QueueUserAPC        = 4,    ///< APC injection
    SetWindowsHookEx    = 5,    ///< Windows hook
    ReflectiveLoading   = 6,    ///< Reflective DLL
    ThreadHijacking     = 7,    ///< Thread execution hijacking
    SectionMapping      = 8     ///< Section view mapping
};

/**
 * @brief Web injection type
 */
enum class WebInjectType : uint8_t {
    Unknown         = 0,
    FormGrabber     = 1,    ///< Form data capture
    HTMLInjection   = 2,    ///< HTML content injection
    JSInjection     = 3,    ///< JavaScript injection
    DOMManipulation = 4,    ///< DOM modification
    ScreenCapture   = 5,    ///< Screenshot of page
    VideoCapture    = 6     ///< Video recording
};

/**
 * @brief Detection action
 */
enum class DetectionAction : uint8_t {
    None            = 0,
    Alert           = 1,    ///< Alert only
    Block           = 2,    ///< Block operation
    Quarantine      = 3,    ///< Quarantine process
    Terminate       = 4,    ///< Terminate process
    Remediate       = 5     ///< Full remediation
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
 * @brief Process indicator
 */
struct ProcessIndicator {
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Parent PID
    uint32_t parentPid = 0;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief Integrity level
    uint32_t integrityLevel = 0;
    
    /// @brief Is elevated
    bool isElevated = false;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief File hash
    Hash256 fileHash{};
    
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
 * @brief Memory region info
 */
struct MemoryRegionInfo {
    /// @brief Base address
    uint64_t baseAddress = 0;
    
    /// @brief Region size
    uint64_t regionSize = 0;
    
    /// @brief Protection flags
    uint32_t protection = 0;
    
    /// @brief State
    uint32_t state = 0;
    
    /// @brief Type
    uint32_t type = 0;
    
    /// @brief Associated module
    std::wstring moduleName;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Is private
    bool isPrivate = false;
    
    /// @brief Contains shellcode
    bool hasShellcode = false;
    
    /// @brief Entropy
    double entropy = 0.0;
    
    /// @brief Suspicious strings found
    std::vector<std::string> suspiciousStrings;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief API hook info
 */
struct ApiHookInfo {
    /// @brief Module name (e.g., "ntdll.dll")
    std::wstring moduleName;
    
    /// @brief Function name (e.g., "NtCreateFile")
    std::string functionName;
    
    /// @brief Original address
    uint64_t originalAddress = 0;
    
    /// @brief Hooked address
    uint64_t hookedAddress = 0;
    
    /// @brief Hook type
    HookType hookType = HookType::Unknown;
    
    /// @brief Hook destination module
    std::wstring hookDestModule;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Confidence
    double confidence = 0.0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Web injection info
 */
struct WebInjectionInfo {
    /// @brief Target URL pattern
    std::string urlPattern;
    
    /// @brief Target domain
    std::string targetDomain;
    
    /// @brief Injection type
    WebInjectType injectType = WebInjectType::Unknown;
    
    /// @brief Injected content (truncated)
    std::string injectedContent;
    
    /// @brief Target fields
    std::vector<std::string> targetFields;
    
    /// @brief Is active
    bool isActive = false;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Network connection info
 */
struct NetworkConnectionInfo {
    /// @brief Remote IP
    std::string remoteIP;
    
    /// @brief Remote port
    uint16_t remotePort = 0;
    
    /// @brief Local port
    uint16_t localPort = 0;
    
    /// @brief Protocol (TCP/UDP)
    uint8_t protocol = 0;
    
    /// @brief Is C2 communication
    bool isC2 = false;
    
    /// @brief Is DGA domain
    bool isDGA = false;
    
    /// @brief Domain name
    std::string domainName;
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Connection time
    SystemTimePoint connectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Threat indicator
 */
struct ThreatIndicator {
    /// @brief Indicator type
    std::string indicatorType;
    
    /// @brief Indicator value
    std::string indicatorValue;
    
    /// @brief Source
    std::string source;
    
    /// @brief Confidence
    double confidence = 0.0;
    
    /// @brief Description
    std::string description;
};

/**
 * @brief Detection result
 */
struct DetectionResult {
    /// @brief Detection ID
    std::string detectionId;
    
    /// @brief Is threat detected
    bool isThreatDetected = false;
    
    /// @brief Trojan family
    TrojanFamily family = TrojanFamily::Unknown;
    
    /// @brief Family name
    std::string familyName;
    
    /// @brief Variant name
    std::string variantName;
    
    /// @brief Severity
    ThreatSeverity severity = ThreatSeverity::None;
    
    /// @brief Threat score (0-100)
    double threatScore = 0.0;
    
    /// @brief Confidence score (0-1)
    double confidenceScore = 0.0;
    
    /// @brief Detection methods used
    std::vector<DetectionMethod> detectionMethods;
    
    /// @brief Action taken
    DetectionAction actionTaken = DetectionAction::None;
    
    /// @brief Process info
    ProcessIndicator processInfo;
    
    /// @brief Suspicious memory regions
    std::vector<MemoryRegionInfo> suspiciousMemory;
    
    /// @brief Detected API hooks
    std::vector<ApiHookInfo> detectedHooks;
    
    /// @brief Web injections
    std::vector<WebInjectionInfo> webInjections;
    
    /// @brief Network connections
    std::vector<NetworkConnectionInfo> networkConnections;
    
    /// @brief Threat indicators
    std::vector<ThreatIndicator> indicators;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Analysis duration
    std::chrono::milliseconds analysisDuration{0};
    
    /// @brief Affected files
    std::vector<std::wstring> affectedFiles;
    
    /// @brief Affected registry keys
    std::vector<std::wstring> affectedRegistry;
    
    /// @brief Remediation advice
    std::string remediationAdvice;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Whitelist reason
    std::string whitelistReason;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection statistics
 */
struct DetectionStatistics {
    /// @brief Total scans
    std::atomic<uint64_t> totalScans{0};
    
    /// @brief Threats detected
    std::atomic<uint64_t> threatsDetected{0};
    
    /// @brief Threats quarantined
    std::atomic<uint64_t> threatsQuarantined{0};
    
    /// @brief Threats remediated
    std::atomic<uint64_t> threatsRemediated{0};
    
    /// @brief False positives reported
    std::atomic<uint64_t> falsePositives{0};
    
    /// @brief Whitelist hits
    std::atomic<uint64_t> whitelistHits{0};
    
    /// @brief Detections by family
    std::array<std::atomic<uint64_t>, 32> byFamily{};
    
    /// @brief Detections by method
    std::array<std::atomic<uint64_t>, 16> byMethod{};
    
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
 * @brief Detector configuration
 */
struct BankingTrojanDetectorConfiguration {
    /// @brief Enable real-time protection
    bool enableRealTimeProtection = true;
    
    /// @brief Enable behavioral analysis
    bool enableBehavioralAnalysis = true;
    
    /// @brief Enable heuristic engine
    bool enableHeuristics = true;
    
    /// @brief Enable machine learning
    bool enableMachineLearning = true;
    
    /// @brief Enable memory scanning
    bool enableMemoryScanning = true;
    
    /// @brief Enable API hook detection
    bool enableAPIHookDetection = true;
    
    /// @brief Enable web injection detection
    bool enableWebInjectDetection = true;
    
    /// @brief Enable network monitoring
    bool enableNetworkMonitoring = true;
    
    /// @brief Enable threat intel lookup
    bool enableThreatIntel = true;
    
    /// @brief Threat score threshold
    double threatScoreThreshold = BankingTrojanConstants::THREAT_SCORE_MEDIUM;
    
    /// @brief Confidence threshold
    double confidenceThreshold = BankingTrojanConstants::MIN_CONFIDENCE;
    
    /// @brief Auto-quarantine on detection
    bool autoQuarantine = true;
    
    /// @brief Auto-terminate malicious process
    bool autoTerminate = false;
    
    /// @brief Block C2 communications
    bool blockC2 = true;
    
    /// @brief Remove persistence mechanisms
    bool removePersistence = true;
    
    /// @brief Whitelisted processes
    std::vector<std::wstring> whitelistedProcesses;
    
    /// @brief YARA rules path
    std::wstring yaraRulesPath;
    
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
using DetectionCallback = std::function<void(const DetectionResult&)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int errorCode)>;

/// @brief Progress callback
using ProgressCallback = std::function<void(uint32_t scanned, uint32_t total)>;

// ============================================================================
// BANKING TROJAN DETECTOR CLASS
// ============================================================================

/**
 * @class BankingTrojanDetector
 * @brief Enterprise-grade banking trojan detection engine
 *
 * Provides comprehensive detection for banking malware using multiple
 * detection techniques including signatures, heuristics, behavioral
 * analysis, and machine learning.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& detector = BankingTrojanDetector::Instance();
 *     detector.Initialize(config);
 *     
 *     // Analyze specific process
 *     auto result = detector.AnalyzeProcess(pid);
 *     if (result.isThreatDetected) {
 *         // Handle threat
 *     }
 * @endcode
 */
class BankingTrojanDetector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static BankingTrojanDetector& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    BankingTrojanDetector(const BankingTrojanDetector&) = delete;
    BankingTrojanDetector& operator=(const BankingTrojanDetector&) = delete;
    BankingTrojanDetector(BankingTrojanDetector&&) = delete;
    BankingTrojanDetector& operator=(BankingTrojanDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize detector
     */
    [[nodiscard]] bool Initialize(const BankingTrojanDetectorConfiguration& config = {});
    
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
     * @brief Start real-time protection
     */
    [[nodiscard]] bool Start();
    
    /**
     * @brief Stop real-time protection
     */
    [[nodiscard]] bool Stop();
    
    /**
     * @brief Pause protection
     */
    void Pause();
    
    /**
     * @brief Resume protection
     */
    void Resume();
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool UpdateConfiguration(const BankingTrojanDetectorConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] BankingTrojanDetectorConfiguration GetConfiguration() const;
    
    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze specific process
     */
    [[nodiscard]] DetectionResult AnalyzeProcess(uint32_t processId);
    
    /**
     * @brief Analyze process by name
     */
    [[nodiscard]] DetectionResult AnalyzeProcessByName(std::wstring_view processName);
    
    /**
     * @brief Analyze process by path
     */
    [[nodiscard]] DetectionResult AnalyzeProcessByPath(const std::filesystem::path& path);
    
    /**
     * @brief Scan all running processes
     */
    [[nodiscard]] std::vector<DetectionResult> ScanAllProcesses();
    
    /**
     * @brief Scan browser processes
     */
    [[nodiscard]] std::vector<DetectionResult> ScanBrowserProcesses();
    
    // ========================================================================
    // MEMORY ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze process memory
     */
    [[nodiscard]] DetectionResult AnalyzeProcessMemory(uint32_t processId);
    
    /**
     * @brief Scan memory regions
     */
    [[nodiscard]] std::vector<MemoryRegionInfo> ScanMemoryRegions(uint32_t processId);
    
    /**
     * @brief Detect shellcode in memory
     */
    [[nodiscard]] bool DetectShellcode(uint32_t processId, uint64_t address, size_t size);
    
    // ========================================================================
    // HOOK DETECTION
    // ========================================================================
    
    /**
     * @brief Detect API hooks in process
     */
    [[nodiscard]] std::vector<ApiHookInfo> DetectAPIHooks(uint32_t processId);
    
    /**
     * @brief Detect hooks in specific module
     */
    [[nodiscard]] std::vector<ApiHookInfo> DetectModuleHooks(
        uint32_t processId, std::wstring_view moduleName);
    
    /**
     * @brief Restore hooked function
     */
    [[nodiscard]] bool RestoreHook(uint32_t processId, const ApiHookInfo& hook);
    
    // ========================================================================
    // WEB INJECTION DETECTION
    // ========================================================================
    
    /**
     * @brief Detect web injections
     */
    [[nodiscard]] std::vector<WebInjectionInfo> DetectWebInjections(uint32_t processId);
    
    /**
     * @brief Detect form grabbers
     */
    [[nodiscard]] bool DetectFormGrabber(uint32_t processId);
    
    // ========================================================================
    // NETWORK ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze network connections
     */
    [[nodiscard]] std::vector<NetworkConnectionInfo> AnalyzeNetworkConnections(
        uint32_t processId);
    
    /**
     * @brief Detect C2 communication
     */
    [[nodiscard]] bool DetectC2Communication(uint32_t processId);
    
    /**
     * @brief Detect DGA domains
     */
    [[nodiscard]] std::vector<std::string> DetectDGADomains(uint32_t processId);
    
    // ========================================================================
    // FAMILY IDENTIFICATION
    // ========================================================================
    
    /**
     * @brief Identify trojan family
     */
    [[nodiscard]] TrojanFamily IdentifyFamily(uint32_t processId);
    
    /**
     * @brief Get family name
     */
    [[nodiscard]] static std::string_view GetFamilyName(TrojanFamily family) noexcept;
    
    // ========================================================================
    // REMEDIATION
    // ========================================================================
    
    /**
     * @brief Quarantine process
     */
    [[nodiscard]] bool QuarantineProcess(uint32_t processId);
    
    /**
     * @brief Terminate process
     */
    [[nodiscard]] bool TerminateProcess(uint32_t processId);
    
    /**
     * @brief Remove persistence
     */
    [[nodiscard]] bool RemovePersistence(uint32_t processId);
    
    /**
     * @brief Full remediation
     */
    [[nodiscard]] bool Remediate(const DetectionResult& detection);
    
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
     * @brief Remove from whitelist
     */
    void RemoveFromWhitelist(uint32_t processId);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register detection callback
     */
    void RegisterDetectionCallback(DetectionCallback callback);
    
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
    [[nodiscard]] DetectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get recent detections
     */
    [[nodiscard]] std::vector<DetectionResult> GetRecentDetections(
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
    
    BankingTrojanDetector();
    ~BankingTrojanDetector();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<BankingTrojanDetectorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get trojan family name
 */
[[nodiscard]] std::string_view GetTrojanFamilyName(TrojanFamily family) noexcept;

/**
 * @brief Get detection method name
 */
[[nodiscard]] std::string_view GetDetectionMethodName(DetectionMethod method) noexcept;

/**
 * @brief Get severity name
 */
[[nodiscard]] std::string_view GetSeverityName(ThreatSeverity severity) noexcept;

/**
 * @brief Get hook type name
 */
[[nodiscard]] std::string_view GetHookTypeName(HookType type) noexcept;

/**
 * @brief Get injection technique name
 */
[[nodiscard]] std::string_view GetInjectionTechniqueName(InjectionTechnique tech) noexcept;

/**
 * @brief Get web inject type name
 */
[[nodiscard]] std::string_view GetWebInjectTypeName(WebInjectType type) noexcept;

/**
 * @brief Get action name
 */
[[nodiscard]] std::string_view GetActionName(DetectionAction action) noexcept;

/**
 * @brief Check if process is a browser
 */
[[nodiscard]] bool IsBrowserProcess(std::wstring_view processName) noexcept;

/**
 * @brief Calculate threat score
 */
[[nodiscard]] double CalculateThreatScore(const DetectionResult& result);

/**
 * @brief Determine severity from threat score
 */
[[nodiscard]] ThreatSeverity DetermineSeverity(double threatScore) noexcept;

}  // namespace Banking
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Analyze process for banking trojans
 */
#define SS_ANALYZE_BANKING_TROJAN(pid) \
    ::ShadowStrike::Banking::BankingTrojanDetector::Instance().AnalyzeProcess(pid)

/**
 * @brief Scan all processes for banking trojans
 */
#define SS_SCAN_BANKING_TROJANS() \
    ::ShadowStrike::Banking::BankingTrojanDetector::Instance().ScanAllProcesses()
