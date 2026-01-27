/**
 * ============================================================================
 * ShadowStrike NGAV - CHROME EXTENSION SCANNER MODULE
 * ============================================================================
 *
 * @file ChromeExtensionScanner.hpp
 * @brief Enterprise-grade Chrome/Chromium extension security scanner for
 *        detecting malicious, sideloaded, and over-permissioned extensions.
 *
 * Provides comprehensive extension analysis including permission auditing,
 * malware detection, behavioral analysis, and policy compliance checking.
 *
 * SCANNING CAPABILITIES:
 * ======================
 *
 * 1. PERMISSION ANALYSIS
 *    - Dangerous permission detection
 *    - Permission escalation detection
 *    - Over-privilege analysis
 *    - Host permission auditing
 *    - Content script analysis
 *
 * 2. MALWARE DETECTION
 *    - Known malicious extension IDs
 *    - Signature-based detection
 *    - Behavioral pattern matching
 *    - Obfuscation detection
 *    - Cryptominer detection
 *
 * 3. CODE ANALYSIS
 *    - JavaScript static analysis
 *    - Obfuscation detection
 *    - Suspicious API usage
 *    - Data exfiltration patterns
 *    - Injection code detection
 *
 * 4. METADATA ANALYSIS
 *    - Manifest parsing
 *    - Version validation
 *    - Update URL verification
 *    - Developer verification
 *    - Web Store validation
 *
 * 5. BEHAVIORAL ANALYSIS
 *    - Network activity monitoring
 *    - Storage access patterns
 *    - DOM manipulation tracking
 *    - Request interception
 *
 * SUPPORTED BROWSERS:
 * ===================
 * - Google Chrome
 * - Microsoft Edge (Chromium)
 * - Brave Browser
 * - Opera Browser
 * - Vivaldi Browser
 *
 * INTEGRATION:
 * ============
 * - HashStore for known-bad extension hashes
 * - ThreatIntel for malicious extension IOCs
 * - PatternStore for detection patterns
 *
 * @note Scans all user profiles.
 * @note Thread-safe singleton design.
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
#include "../Utils/FileUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::WebBrowser {
    class ChromeExtensionScannerImpl;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ChromeExtensionConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum extension size for analysis
    inline constexpr size_t MAX_EXTENSION_SIZE = 100 * 1024 * 1024;  // 100MB
    
    /// @brief Maximum JavaScript file size to analyze
    inline constexpr size_t MAX_JS_FILE_SIZE = 10 * 1024 * 1024;  // 10MB

    /// @brief Dangerous permissions
    inline constexpr const char* DANGEROUS_PERMISSIONS[] = {
        "tabs", "webRequest", "webRequestBlocking",
        "cookies", "history", "bookmarks",
        "<all_urls>", "*://*/*", "debugger",
        "clipboardRead", "clipboardWrite",
        "nativeMessaging", "management",
        "proxy", "privacy", "downloads"
    };

    /// @brief Critical permissions
    inline constexpr const char* CRITICAL_PERMISSIONS[] = {
        "webRequest", "webRequestBlocking",
        "<all_urls>", "*://*/*",
        "debugger", "nativeMessaging"
    };

    /// @brief Chrome profile subpaths
    inline constexpr const char* CHROME_PROFILE_PATHS[] = {
        "\\AppData\\Local\\Google\\Chrome\\User Data",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data",
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data",
        "\\AppData\\Roaming\\Opera Software\\Opera Stable"
    };

}  // namespace ChromeExtensionConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Extension verdict
 */
enum class ExtensionVerdict : uint8_t {
    Safe            = 0,    ///< Extension is safe
    Suspicious      = 1,    ///< Suspicious characteristics
    Malicious       = 2,    ///< Known malware
    OverPrivileged  = 3,    ///< Too many permissions
    Sideloaded      = 4,    ///< Not from store
    PolicyViolation = 5,    ///< Violates enterprise policy
    Unknown         = 6     ///< Unknown/unverified
};

/**
 * @brief Extension risk level
 */
enum class ExtensionRiskLevel : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4
};

/**
 * @brief Extension source
 */
enum class ExtensionSource : uint8_t {
    Unknown         = 0,
    ChromeWebStore  = 1,
    EdgeAddons      = 2,
    Sideloaded      = 3,
    Enterprise      = 4,
    Development     = 5
};

/**
 * @brief Browser type
 */
enum class ChromiumBrowser : uint8_t {
    Unknown     = 0,
    Chrome      = 1,
    Edge        = 2,
    Brave       = 3,
    Opera       = 4,
    Vivaldi     = 5
};

/**
 * @brief Permission risk
 */
enum class PermissionRisk : uint8_t {
    Safe        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4
};

/**
 * @brief Scan type
 */
enum class ScanType : uint8_t {
    Quick       = 0,    ///< Metadata only
    Standard    = 1,    ///< Permissions + basic analysis
    Deep        = 2     ///< Full code analysis
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
 * @brief Permission info
 */
struct PermissionInfo {
    /// @brief Permission name
    std::string name;
    
    /// @brief Risk level
    PermissionRisk riskLevel = PermissionRisk::Safe;
    
    /// @brief Description
    std::string description;
    
    /// @brief Is host permission
    bool isHostPermission = false;
    
    /// @brief Is optional
    bool isOptional = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Content script info
 */
struct ContentScriptInfo {
    /// @brief Match patterns
    std::vector<std::string> matches;
    
    /// @brief Exclude matches
    std::vector<std::string> excludeMatches;
    
    /// @brief JavaScript files
    std::vector<std::string> jsFiles;
    
    /// @brief CSS files
    std::vector<std::string> cssFiles;
    
    /// @brief Run at (document_start, document_end, document_idle)
    std::string runAt;
    
    /// @brief All frames
    bool allFrames = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Extension manifest info
 */
struct ManifestInfo {
    /// @brief Manifest version
    int manifestVersion = 3;
    
    /// @brief Extension name
    std::string name;
    
    /// @brief Version
    std::string version;
    
    /// @brief Description
    std::string description;
    
    /// @brief Author
    std::string author;
    
    /// @brief Permissions
    std::vector<std::string> permissions;
    
    /// @brief Optional permissions
    std::vector<std::string> optionalPermissions;
    
    /// @brief Host permissions
    std::vector<std::string> hostPermissions;
    
    /// @brief Content scripts
    std::vector<ContentScriptInfo> contentScripts;
    
    /// @brief Background scripts
    std::vector<std::string> backgroundScripts;
    
    /// @brief Service worker
    std::string serviceWorker;
    
    /// @brief Update URL
    std::string updateUrl;
    
    /// @brief Homepage URL
    std::string homepageUrl;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Code analysis result
 */
struct CodeAnalysisResult {
    /// @brief Total JavaScript files
    size_t totalJsFiles = 0;
    
    /// @brief Total code size (bytes)
    size_t totalCodeSize = 0;
    
    /// @brief Is obfuscated
    bool isObfuscated = false;
    
    /// @brief Obfuscation type
    std::string obfuscationType;
    
    /// @brief Has eval usage
    bool hasEval = false;
    
    /// @brief Has dynamic script loading
    bool hasDynamicScriptLoading = false;
    
    /// @brief Has data exfiltration patterns
    bool hasDataExfiltration = false;
    
    /// @brief Has cryptominer code
    bool hasCryptominer = false;
    
    /// @brief Has keylogger patterns
    bool hasKeylogger = false;
    
    /// @brief Suspicious API calls
    std::vector<std::string> suspiciousAPIs;
    
    /// @brief Suspicious URLs
    std::vector<std::string> suspiciousUrls;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Extension info
 */
struct ExtensionInfo {
    /// @brief Extension ID
    std::string id;
    
    /// @brief Name
    std::string name;
    
    /// @brief Version
    std::string version;
    
    /// @brief Description
    std::string description;
    
    /// @brief Extension path
    fs::path extensionPath;
    
    /// @brief Browser
    ChromiumBrowser browser = ChromiumBrowser::Unknown;
    
    /// @brief Profile name
    std::string profileName;
    
    /// @brief Source
    ExtensionSource source = ExtensionSource::Unknown;
    
    /// @brief Permissions
    std::vector<std::string> permissions;
    
    /// @brief Permission details
    std::vector<PermissionInfo> permissionDetails;
    
    /// @brief Manifest info
    ManifestInfo manifest;
    
    /// @brief Is sideloaded
    bool isSideloaded = false;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Is enabled
    bool isEnabled = true;
    
    /// @brief Installed time
    SystemTimePoint installedTime;
    
    /// @brief Last updated
    SystemTimePoint lastUpdated;
    
    /// @brief Web Store URL
    std::string webStoreUrl;
    
    /// @brief File hashes
    std::map<std::string, std::string> fileHashes;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Extension scan result
 */
struct ExtensionScanResult {
    /// @brief Extension info
    ExtensionInfo info;
    
    /// @brief Verdict
    ExtensionVerdict verdict = ExtensionVerdict::Unknown;
    
    /// @brief Risk level
    ExtensionRiskLevel riskLevel = ExtensionRiskLevel::None;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Code analysis
    CodeAnalysisResult codeAnalysis;
    
    /// @brief Dangerous permissions count
    int dangerousPermissionsCount = 0;
    
    /// @brief Critical permissions count
    int criticalPermissionsCount = 0;
    
    /// @brief Issues found
    std::vector<std::string> issues;
    
    /// @brief Recommendations
    std::vector<std::string> recommendations;
    
    /// @brief Matched threat intel
    std::vector<std::string> threatIntelMatches;
    
    /// @brief Scan time
    std::chrono::microseconds scanDuration{0};
    
    [[nodiscard]] bool IsClean() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct ChromeExtensionScannerStatistics {
    std::atomic<uint64_t> totalScanned{0};
    std::atomic<uint64_t> safeFound{0};
    std::atomic<uint64_t> suspiciousFound{0};
    std::atomic<uint64_t> maliciousFound{0};
    std::atomic<uint64_t> sideloadedFound{0};
    std::atomic<uint64_t> overPrivilegedFound{0};
    std::atomic<uint64_t> profilesScanned{0};
    std::atomic<uint64_t> jsFilesAnalyzed{0};
    std::atomic<uint64_t> obfuscatedFound{0};
    std::atomic<uint64_t> cryptominersFound{0};
    std::array<std::atomic<uint64_t>, 8> byVerdict{};
    std::array<std::atomic<uint64_t>, 8> byBrowser{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ChromeExtensionScannerConfiguration {
    /// @brief Enable scanner
    bool enabled = true;
    
    /// @brief Scan type
    ScanType scanType = ScanType::Standard;
    
    /// @brief Scan Chrome
    bool scanChrome = true;
    
    /// @brief Scan Edge
    bool scanEdge = true;
    
    /// @brief Scan Brave
    bool scanBrave = true;
    
    /// @brief Scan Opera
    bool scanOpera = true;
    
    /// @brief Analyze code
    bool analyzeCode = true;
    
    /// @brief Flag sideloaded
    bool flagSideloaded = true;
    
    /// @brief Check threat intel
    bool checkThreatIntel = true;
    
    /// @brief Block malicious
    bool blockMalicious = false;
    
    /// @brief Allowed extension IDs
    std::vector<std::string> allowedExtensionIds;
    
    /// @brief Blocked extension IDs
    std::vector<std::string> blockedExtensionIds;
    
    /// @brief Max code size to analyze
    size_t maxCodeSizeToAnalyze = ChromeExtensionConstants::MAX_JS_FILE_SIZE;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const ExtensionScanResult&)>;
using MaliciousFoundCallback = std::function<void(const ExtensionInfo&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// CHROME EXTENSION SCANNER CLASS
// ============================================================================

/**
 * @class ChromeExtensionScanner
 * @brief Enterprise Chrome extension security scanner
 */
class ChromeExtensionScanner final {
public:
    [[nodiscard]] static ChromeExtensionScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ChromeExtensionScanner(const ChromeExtensionScanner&) = delete;
    ChromeExtensionScanner& operator=(const ChromeExtensionScanner&) = delete;
    ChromeExtensionScanner(ChromeExtensionScanner&&) = delete;
    ChromeExtensionScanner& operator=(ChromeExtensionScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ChromeExtensionScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const ChromeExtensionScannerConfiguration& config);
    [[nodiscard]] ChromeExtensionScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan all extensions
    [[nodiscard]] std::vector<ExtensionScanResult> ScanAll();
    
    /// @brief Scan extensions for specific browser
    [[nodiscard]] std::vector<ExtensionScanResult> ScanBrowser(ChromiumBrowser browser);
    
    /// @brief Scan specific extension folder
    [[nodiscard]] ExtensionScanResult ScanExtension(const fs::path& extensionPath);
    
    /// @brief Analyze extension folder
    [[nodiscard]] ExtensionInfo AnalyzeFolder(const std::wstring& path);
    
    /// @brief Analyze extension folder (fs::path)
    [[nodiscard]] ExtensionInfo AnalyzeFolder(const fs::path& path);
    
    /// @brief Get all installed extensions
    [[nodiscard]] std::vector<ExtensionInfo> GetInstalledExtensions();
    
    /// @brief Get extensions for browser
    [[nodiscard]] std::vector<ExtensionInfo> GetExtensionsForBrowser(ChromiumBrowser browser);

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Analyze extension permissions
    [[nodiscard]] std::vector<PermissionInfo> AnalyzePermissions(
        const std::vector<std::string>& permissions);
    
    /// @brief Analyze extension code
    [[nodiscard]] CodeAnalysisResult AnalyzeCode(const fs::path& extensionPath);
    
    /// @brief Check if extension is malicious
    [[nodiscard]] bool IsMalicious(const std::string& extensionId);
    
    /// @brief Get permission risk
    [[nodiscard]] PermissionRisk GetPermissionRisk(const std::string& permission);

    // ========================================================================
    // PROFILE DISCOVERY
    // ========================================================================
    
    /// @brief Get browser profiles
    [[nodiscard]] std::vector<fs::path> GetBrowserProfiles(ChromiumBrowser browser);
    
    /// @brief Get extension directories
    [[nodiscard]] std::vector<fs::path> GetExtensionDirectories(
        ChromiumBrowser browser,
        const std::string& profileName = "Default");

    // ========================================================================
    // POLICY
    // ========================================================================
    
    /// @brief Add extension to allowed list
    [[nodiscard]] bool AllowExtension(const std::string& extensionId);
    
    /// @brief Block extension
    [[nodiscard]] bool BlockExtension(const std::string& extensionId);
    
    /// @brief Is extension allowed
    [[nodiscard]] bool IsExtensionAllowed(const std::string& extensionId) const;
    
    /// @brief Is extension blocked
    [[nodiscard]] bool IsExtensionBlocked(const std::string& extensionId) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterMaliciousCallback(MaliciousFoundCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ChromeExtensionScannerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ChromeExtensionScanner();
    ~ChromeExtensionScanner();
    
    std::unique_ptr<ChromeExtensionScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetExtensionVerdictName(ExtensionVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetExtensionRiskLevelName(ExtensionRiskLevel level) noexcept;
[[nodiscard]] std::string_view GetExtensionSourceName(ExtensionSource source) noexcept;
[[nodiscard]] std::string_view GetChromiumBrowserName(ChromiumBrowser browser) noexcept;
[[nodiscard]] std::string_view GetPermissionRiskName(PermissionRisk risk) noexcept;

/// @brief Parse manifest.json
[[nodiscard]] std::optional<ManifestInfo> ParseManifest(const fs::path& manifestPath);

/// @brief Is dangerous permission
[[nodiscard]] bool IsDangerousPermission(const std::string& permission);

/// @brief Is critical permission
[[nodiscard]] bool IsCriticalPermission(const std::string& permission);

/// @brief Get Chrome Web Store URL
[[nodiscard]] std::string GetWebStoreUrl(const std::string& extensionId);

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CHROME_EXT_SCAN_ALL() \
    ::ShadowStrike::WebBrowser::ChromeExtensionScanner::Instance().ScanAll()

#define SS_CHROME_EXT_IS_MALICIOUS(id) \
    ::ShadowStrike::WebBrowser::ChromeExtensionScanner::Instance().IsMalicious(id)

#define SS_CHROME_EXT_BLOCK(id) \
    ::ShadowStrike::WebBrowser::ChromeExtensionScanner::Instance().BlockExtension(id)
