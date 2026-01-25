/**
 * ============================================================================
 * ShadowStrike NGAV - JAVASCRIPT SCANNER MODULE
 * ============================================================================
 *
 * @file JavaScriptScanner.hpp
 * @brief Enterprise-grade JavaScript/JScript analysis engine for detection of
 *        malicious scripts targeting Windows Script Host and browser environments.
 *
 * Provides comprehensive detection of JavaScript-based malware including
 * ActiveX abuse, eval() exploitation, and obfuscated downloaders.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. WINDOWS SCRIPT HOST (WSH) MALWARE
 *    - WScript.Shell execution
 *    - ActiveXObject instantiation
 *    - FileSystemObject abuse
 *    - Shell.Application exploitation
 *    - ADODB.Stream file operations
 *    - WMI query execution
 *
 * 2. OBFUSCATION DETECTION
 *    - eval() chain analysis
 *    - String splitting/concatenation
 *    - Character code encoding (fromCharCode)
 *    - Unicode escape sequences
 *    - Hex/octal encoding
 *    - JSFuck/AAEncode detection
 *    - JJEncode detection
 *
 * 3. DOWNLOADER DETECTION
 *    - XMLHttpRequest abuse
 *    - MSXML2.XMLHTTP usage
 *    - WinHTTP.WinHttpRequest
 *    - fetch() API monitoring
 *    - Network callback patterns
 *
 * 4. MALWARE FAMILY DETECTION
 *    - Nemucod/Locky droppers
 *    - RAA ransomware
 *    - WSH-based RATs
 *    - Cryptocurrency miners
 *    - Browser hijackers
 *
 * 5. BROWSER JAVASCRIPT THREATS
 *    - Cryptojacking scripts
 *    - Drive-by download triggers
 *    - Browser exploit kits
 *    - Malvertising payloads
 *    - Form grabbers
 *
 * 6. NODE.JS SECURITY
 *    - Malicious npm packages
 *    - child_process abuse
 *    - fs module exploitation
 *    - Supply chain attacks
 *
 * INTEGRATION:
 * ============
 * - PatternStore for JS malware patterns
 * - SignatureStore for family signatures
 * - ThreatIntel for IOC correlation
 *
 * @note Supports both file-based and memory scanning.
 * @note Includes lightweight JS emulation for deobfuscation.
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
#include "../Utils/StringUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Scripts {
    class JavaScriptScannerImpl;
}

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace JSConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum script size (10 MB)
    inline constexpr size_t MAX_SCRIPT_SIZE = 10 * 1024 * 1024;
    
    /// @brief Maximum token analysis depth
    inline constexpr size_t MAX_TOKEN_DEPTH = 1000;
    
    /// @brief Maximum recursion for deobfuscation
    inline constexpr size_t MAX_DEOBFUSCATION_DEPTH = 32;
    
    /// @brief Emulation timeout (ms)
    inline constexpr uint32_t EMULATION_TIMEOUT_MS = 2000;
    
    /// @brief High entropy threshold (obfuscation indicator)
    inline constexpr double ENTROPY_THRESHOLD_OBFUSCATED = 5.5;
    
    /// @brief Suspicious ActiveX objects
    inline constexpr const char* SUSPICIOUS_ACTIVEX[] = {
        "WScript.Shell",
        "Scripting.FileSystemObject",
        "Shell.Application",
        "ADODB.Stream",
        "MSXML2.XMLHTTP",
        "WinHttp.WinHttpRequest",
        "Scripting.Dictionary",
        "Schedule.Service",
    };

}  // namespace JSConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief JavaScript engine/runtime type
 */
enum class JSEngineType : uint8_t {
    Unknown         = 0,
    JScriptWSH      = 1,    ///< Windows Script Host (JScript)
    NodeJS          = 2,    ///< Node.js runtime
    BrowserV8       = 3,    ///< V8 (Chrome)
    BrowserSpider   = 4,    ///< SpiderMonkey (Firefox)
    BrowserJSC      = 5,    ///< JavaScriptCore (Safari)
    BrowserChakra   = 6,    ///< Chakra (Edge)
    Electron        = 7,    ///< Electron app
    PDF             = 8     ///< PDF JavaScript
};

/**
 * @brief Obfuscation technique
 */
enum class JSObfuscationType : uint8_t {
    None                = 0,
    EvalChain           = 1,    ///< Nested eval() calls
    StringSplitting     = 2,    ///< Split strings concatenated
    CharCodeEncoding    = 3,    ///< String.fromCharCode
    UnicodeEscape       = 4,    ///< \uXXXX sequences
    HexEncoding         = 5,    ///< \xXX sequences
    OctalEncoding       = 6,    ///< Octal escape sequences
    Base64              = 7,    ///< atob() decoding
    JSFuck              = 8,    ///< JSFuck encoding
    AAEncode            = 9,    ///< AAEncode
    JJEncode            = 10,   ///< JJEncode
    PackerCompression   = 11,   ///< JavaScript packers (Dean Edwards)
    VariableRenaming    = 12,   ///< Meaningless variable names
    ControlFlowFlatten  = 13,   ///< Control flow flattening
    DeadCodeInjection   = 14,   ///< Dead code insertion
    Custom              = 255   ///< Custom/unknown obfuscation
};

/**
 * @brief Threat category
 */
enum class JSThreatCategory : uint8_t {
    None            = 0,
    Downloader      = 1,    ///< Downloads and executes payload
    Dropper         = 2,    ///< Drops files to disk
    Ransomware      = 3,    ///< Ransomware payload
    RAT             = 4,    ///< Remote access trojan
    CryptoMiner     = 5,    ///< Cryptocurrency miner
    InfoStealer     = 6,    ///< Information stealer
    BrowserHijacker = 7,    ///< Browser settings modification
    Adware          = 8,    ///< Advertising injection
    ExploitKit      = 9,    ///< Browser exploit delivery
    FormGrabber     = 10,   ///< Form/input capture
    Keylogger       = 11,   ///< Keystroke logging
    Reconnaissance  = 12,   ///< System enumeration
    Persistence     = 13,   ///< Persistence mechanism
    Worm            = 14    ///< Self-propagating
};

/**
 * @brief Scan status
 */
enum class JSScanStatus : uint8_t {
    Clean               = 0,
    Suspicious          = 1,
    Malicious           = 2,
    ErrorFileAccess     = 3,
    ErrorTimeout        = 4,
    ErrorInternal       = 5,
    SkippedWhitelisted  = 6,
    SkippedSizeLimit    = 7
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
 * @brief Obfuscation analysis details
 */
struct JSObfuscationDetails {
    /// @brief Primary obfuscation type
    JSObfuscationType primaryType = JSObfuscationType::None;
    
    /// @brief All detected techniques
    std::vector<JSObfuscationType> detectedTechniques;
    
    /// @brief Entropy score
    double entropyScore = 0.0;
    
    /// @brief Obfuscation confidence (0-100)
    double confidence = 0.0;
    
    /// @brief Suspicious token count
    size_t suspiciousTokenCount = 0;
    
    /// @brief Deobfuscation layers applied
    uint32_t deobfuscationLayers = 0;
    
    /// @brief Deobfuscated snippet (preview)
    std::string deobfuscatedSnippet;
    
    /// @brief Was fully deobfuscated
    bool fullyDeobfuscated = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief ActiveX/COM object usage
 */
struct ActiveXUsage {
    /// @brief Object name
    std::string objectName;
    
    /// @brief Method called
    std::string methodCalled;
    
    /// @brief Arguments (if extractable)
    std::vector<std::string> arguments;
    
    /// @brief Line number
    size_t lineNumber = 0;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Suspicion reason
    std::string suspicionReason;
};

/**
 * @brief Network activity detected
 */
struct JSNetworkActivity {
    /// @brief URL or domain
    std::string target;
    
    /// @brief Method (GET, POST, etc.)
    std::string method;
    
    /// @brief API used
    std::string apiUsed;
    
    /// @brief Line number
    size_t lineNumber = 0;
    
    /// @brief Is known malicious
    bool isKnownMalicious = false;
    
    /// @brief ThreatIntel source
    std::string threatIntelSource;
};

/**
 * @brief Scan result
 */
struct JSScanResult {
    /// @brief Scan status
    JSScanStatus status = JSScanStatus::Clean;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Threat category
    JSThreatCategory category = JSThreatCategory::None;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Detected malware family
    std::string detectedFamily;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Description
    std::string description;
    
    /// @brief Target engine type
    JSEngineType targetEngine = JSEngineType::Unknown;
    
    /// @brief File path (empty if memory scan)
    std::filesystem::path filePath;
    
    /// @brief Content hash (SHA-256)
    std::string sha256;
    
    /// @brief Obfuscation details
    JSObfuscationDetails obfuscation;
    
    /// @brief Matched rules/signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Flagged lines (line number, content)
    std::vector<std::pair<size_t, std::string>> flaggedLines;
    
    /// @brief ActiveX/COM usage
    std::vector<ActiveXUsage> activeXUsage;
    
    /// @brief Network activity
    std::vector<JSNetworkActivity> networkActivity;
    
    /// @brief Extracted IOCs
    std::vector<std::string> extractedIOCs;
    
    /// @brief Process ID (if runtime scan)
    uint32_t processId = 0;
    
    /// @brief Scan time
    SystemTimePoint scanTime;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    /**
     * @brief Check if should block execution
     */
    [[nodiscard]] bool ShouldBlock() const noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct JSStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> obfuscatedDetected{0};
    std::atomic<uint64_t> activeXAbuse{0};
    std::atomic<uint64_t> downloadersDetected{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> totalBytesScanned{0};
    std::array<std::atomic<uint64_t>, 16> byEngine{};
    std::array<std::atomic<uint64_t>, 16> byCategory{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct JSScanConfig {
    /// @brief Enable scanning
    bool enabled = true;
    
    /// @brief Block ActiveX usage
    bool blockActiveX = true;
    
    /// @brief Enable deobfuscation
    bool enableDeobfuscation = true;
    
    /// @brief Enable lightweight emulation
    bool enableEmulation = false;
    
    /// @brief Emulation timeout (ms)
    uint32_t emulationTimeoutMs = JSConstants::EMULATION_TIMEOUT_MS;
    
    /// @brief Maximum script size
    size_t maxScriptSize = JSConstants::MAX_SCRIPT_SIZE;
    
    /// @brief Block obfuscated scripts
    bool blockObfuscatedScripts = false;
    
    /// @brief Obfuscation entropy threshold
    double entropyThreshold = JSConstants::ENTROPY_THRESHOLD_OBFUSCATED;
    
    /// @brief Scan browser cache files
    bool scanBrowserCache = true;
    
    /// @brief Allowed ActiveX objects (whitelist)
    std::vector<std::string> allowedActiveX;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const JSScanResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// JAVASCRIPT SCANNER CLASS
// ============================================================================

/**
 * @class JavaScriptScanner
 * @brief Enterprise-grade JavaScript malware detection engine
 */
class JavaScriptScanner final {
public:
    [[nodiscard]] static JavaScriptScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    JavaScriptScanner(const JavaScriptScanner&) = delete;
    JavaScriptScanner& operator=(const JavaScriptScanner&) = delete;
    JavaScriptScanner(JavaScriptScanner&&) = delete;
    JavaScriptScanner& operator=(JavaScriptScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const JSScanConfig& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfig(const JSScanConfig& config);
    [[nodiscard]] JSScanConfig GetConfig() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan JavaScript file
    [[nodiscard]] JSScanResult ScanFile(const std::filesystem::path& path);
    
    /// @brief Scan JavaScript file with process context
    [[nodiscard]] JSScanResult ScanFile(
        const std::filesystem::path& path,
        uint32_t processId);
    
    /// @brief Scan JavaScript content from memory
    [[nodiscard]] JSScanResult ScanMemory(
        std::span<const char> content,
        std::string_view sourceName = "memory");
    
    /// @brief Scan JavaScript content from memory with process context
    [[nodiscard]] JSScanResult ScanMemory(
        std::span<const char> content,
        std::string_view sourceName,
        uint32_t processId);
    
    /// @brief Scan JavaScript string
    [[nodiscard]] JSScanResult ScanString(
        std::string_view content,
        std::string_view sourceName = "string");

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Detect engine type from content
    [[nodiscard]] JSEngineType DetectEngineType(std::string_view content);
    
    /// @brief Analyze obfuscation
    [[nodiscard]] JSObfuscationDetails AnalyzeObfuscation(std::string_view content);
    
    /// @brief Attempt deobfuscation
    [[nodiscard]] std::string Deobfuscate(
        std::string_view content,
        size_t maxDepth = JSConstants::MAX_DEOBFUSCATION_DEPTH);
    
    /// @brief Extract IOCs from script
    [[nodiscard]] std::vector<std::string> ExtractIOCs(std::string_view content);
    
    /// @brief Detect ActiveX usage
    [[nodiscard]] std::vector<ActiveXUsage> DetectActiveXUsage(std::string_view content);
    
    /// @brief Detect network activity patterns
    [[nodiscard]] std::vector<JSNetworkActivity> DetectNetworkActivity(
        std::string_view content);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterCallback(ScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] JSStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    JavaScriptScanner();
    ~JavaScriptScanner();
    
    std::unique_ptr<JavaScriptScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetJSEngineTypeName(JSEngineType type) noexcept;
[[nodiscard]] std::string_view GetJSObfuscationTypeName(JSObfuscationType type) noexcept;
[[nodiscard]] std::string_view GetJSThreatCategoryName(JSThreatCategory cat) noexcept;
[[nodiscard]] std::string_view GetJSScanStatusName(JSScanStatus status) noexcept;
[[nodiscard]] bool IsSuspiciousActiveXObject(std::string_view objectName) noexcept;

}  // namespace Scripts
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_JS_SCAN_FILE(path) \
    ::ShadowStrike::Scripts::JavaScriptScanner::Instance().ScanFile(path)

#define SS_JS_SCAN_MEMORY(content) \
    ::ShadowStrike::Scripts::JavaScriptScanner::Instance().ScanMemory(content)