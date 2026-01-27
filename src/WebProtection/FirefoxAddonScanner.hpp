/**
 * ============================================================================
 * ShadowStrike NGAV - FIREFOX ADDON SCANNER MODULE
 * ============================================================================
 *
 * @file FirefoxAddonScanner.hpp
 * @brief Enterprise-grade Mozilla Firefox add-on security scanner for
 *        detecting malicious, sideloaded, and over-permissioned extensions.
 *
 * Provides comprehensive add-on analysis including XPI parsing, permission
 * auditing, malware detection, and behavioral analysis.
 *
 * SCANNING CAPABILITIES:
 * ======================
 *
 * 1. XPI ANALYSIS
 *    - XPI archive extraction
 *    - Manifest.json parsing
 *    - Legacy install.rdf support
 *    - Signature verification
 *    - Mozilla signing validation
 *
 * 2. PERMISSION ANALYSIS
 *    - WebExtension permissions
 *    - Legacy add-on privileges
 *    - Host permission auditing
 *    - Content script analysis
 *    - Hidden permission detection
 *
 * 3. MALWARE DETECTION
 *    - Known malicious add-on IDs
 *    - Signature-based detection
 *    - Behavioral pattern matching
 *    - Obfuscation detection
 *    - Cryptominer detection
 *
 * 4. CODE ANALYSIS
 *    - JavaScript static analysis
 *    - Obfuscation detection
 *    - Suspicious API usage
 *    - Data exfiltration patterns
 *    - XUL/XPCOM analysis (legacy)
 *
 * 5. METADATA VALIDATION
 *    - Mozilla AMO verification
 *    - Update manifest validation
 *    - Developer verification
 *    - Signature chain validation
 *
 * SUPPORTED VERSIONS:
 * ===================
 * - Firefox 57+ (WebExtensions)
 * - Firefox ESR
 * - Firefox Developer Edition
 * - Tor Browser
 *
 * INTEGRATION:
 * ============
 * - HashStore for known-bad add-on hashes
 * - ThreatIntel for malicious add-on IOCs
 * - PatternStore for detection patterns
 *
 * @note Parses XPI (ZIP) archives.
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
#include "../Utils/ArchiveUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::WebBrowser {
    class FirefoxAddonScannerImpl;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace FirefoxAddonConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum XPI size for analysis
    inline constexpr size_t MAX_XPI_SIZE = 100 * 1024 * 1024;  // 100MB
    
    /// @brief Maximum extracted size
    inline constexpr size_t MAX_EXTRACTED_SIZE = 500 * 1024 * 1024;  // 500MB
    
    /// @brief Mozilla AMO API
    inline constexpr const char* MOZILLA_AMO_API = "https://addons.mozilla.org/api/v5/";

    /// @brief Dangerous permissions
    inline constexpr const char* DANGEROUS_PERMISSIONS[] = {
        "tabs", "webRequest", "webRequestBlocking",
        "cookies", "history", "bookmarks",
        "<all_urls>", "*://*/*", "nativeMessaging",
        "clipboardRead", "clipboardWrite",
        "management", "proxy", "privacy",
        "browserSettings", "downloads"
    };

    /// @brief Firefox profile subpaths
    inline constexpr const char* FIREFOX_PROFILE_PATHS[] = {
        "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
        "\\AppData\\Local\\Mozilla\\Firefox\\Profiles"
    };

}  // namespace FirefoxAddonConstants

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
 * @brief Add-on verdict
 */
enum class AddonVerdict : uint8_t {
    Safe            = 0,    ///< Add-on is safe
    Suspicious      = 1,    ///< Suspicious characteristics
    Malicious       = 2,    ///< Known malware
    OverPrivileged  = 3,    ///< Too many permissions
    Unsigned        = 4,    ///< Not Mozilla signed
    Sideloaded      = 5,    ///< Manually installed
    PolicyViolation = 6,    ///< Violates enterprise policy
    Legacy          = 7,    ///< Legacy XUL add-on
    Unknown         = 8     ///< Unknown/unverified
};

/**
 * @brief Add-on risk level
 */
enum class AddonRiskLevel : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4
};

/**
 * @brief Add-on type
 */
enum class AddonType : uint8_t {
    Unknown         = 0,
    WebExtension    = 1,    ///< Modern WebExtension
    LegacyXUL       = 2,    ///< Legacy XUL add-on
    Theme           = 3,    ///< Theme
    LangPack        = 4,    ///< Language pack
    Dictionary      = 5,    ///< Spell check dictionary
    Plugin          = 6     ///< NPAPI plugin
};

/**
 * @brief Add-on source
 */
enum class AddonSource : uint8_t {
    Unknown         = 0,
    MozillaAMO      = 1,    ///< Mozilla Add-ons
    Sideloaded      = 2,    ///< Manually installed
    Enterprise      = 3,    ///< Enterprise policy
    Development     = 4,    ///< Temporary dev install
    System          = 5     ///< System add-on
};

/**
 * @brief Signature status
 */
enum class SignatureStatus : uint8_t {
    Unknown         = 0,
    Valid           = 1,    ///< Mozilla signed
    Invalid         = 2,    ///< Invalid signature
    Missing         = 3,    ///< No signature
    Expired         = 4,    ///< Expired signature
    Privileged      = 5     ///< Privileged add-on
};

/**
 * @brief Scan type
 */
enum class AddonScanType : uint8_t {
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
struct FirefoxPermissionInfo {
    /// @brief Permission name
    std::string name;
    
    /// @brief Risk level
    AddonRiskLevel riskLevel = AddonRiskLevel::None;
    
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
struct FirefoxContentScript {
    /// @brief Match patterns
    std::vector<std::string> matches;
    
    /// @brief Exclude matches
    std::vector<std::string> excludeMatches;
    
    /// @brief Include globs
    std::vector<std::string> includeGlobs;
    
    /// @brief Exclude globs
    std::vector<std::string> excludeGlobs;
    
    /// @brief JavaScript files
    std::vector<std::string> jsFiles;
    
    /// @brief CSS files
    std::vector<std::string> cssFiles;
    
    /// @brief Run at
    std::string runAt;
    
    /// @brief All frames
    bool allFrames = false;
    
    /// @brief Match about:blank
    bool matchAboutBlank = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Firefox add-on manifest
 */
struct FirefoxManifest {
    /// @brief Manifest version
    int manifestVersion = 2;
    
    /// @brief Add-on ID
    std::string id;
    
    /// @brief Name
    std::string name;
    
    /// @brief Version
    std::string version;
    
    /// @brief Description
    std::string description;
    
    /// @brief Author
    std::string author;
    
    /// @brief Homepage URL
    std::string homepageUrl;
    
    /// @brief Permissions
    std::vector<std::string> permissions;
    
    /// @brief Optional permissions
    std::vector<std::string> optionalPermissions;
    
    /// @brief Host permissions
    std::vector<std::string> hostPermissions;
    
    /// @brief Content scripts
    std::vector<FirefoxContentScript> contentScripts;
    
    /// @brief Background scripts
    std::vector<std::string> backgroundScripts;
    
    /// @brief Background page
    std::string backgroundPage;
    
    /// @brief Browser-specific settings
    std::map<std::string, std::string> browserSpecificSettings;
    
    /// @brief Gecko ID
    std::string geckoId;
    
    /// @brief Strict minimum version
    std::string strictMinVersion;
    
    /// @brief Update URL
    std::string updateUrl;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Signature info
 */
struct SignatureInfo {
    /// @brief Status
    SignatureStatus status = SignatureStatus::Unknown;
    
    /// @brief Signer name
    std::string signerName;
    
    /// @brief Certificate subject
    std::string certificateSubject;
    
    /// @brief Certificate issuer
    std::string certificateIssuer;
    
    /// @brief Valid from
    SystemTimePoint validFrom;
    
    /// @brief Valid to
    SystemTimePoint validTo;
    
    /// @brief Is Mozilla signed
    bool isMozillaSigned = false;
    
    /// @brief Is privileged
    bool isPrivileged = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Code analysis result
 */
struct AddonCodeAnalysis {
    /// @brief Total JavaScript files
    size_t totalJsFiles = 0;
    
    /// @brief Total code size
    size_t totalCodeSize = 0;
    
    /// @brief Is obfuscated
    bool isObfuscated = false;
    
    /// @brief Obfuscation type
    std::string obfuscationType;
    
    /// @brief Has eval usage
    bool hasEval = false;
    
    /// @brief Has dynamic script loading
    bool hasDynamicScriptLoading = false;
    
    /// @brief Has data exfiltration
    bool hasDataExfiltration = false;
    
    /// @brief Has cryptominer
    bool hasCryptominer = false;
    
    /// @brief Suspicious APIs
    std::vector<std::string> suspiciousAPIs;
    
    /// @brief Suspicious URLs
    std::vector<std::string> suspiciousUrls;
    
    /// @brief Risk score
    int riskScore = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Add-on info
 */
struct FirefoxAddonInfo {
    /// @brief Add-on ID
    std::string id;
    
    /// @brief Name
    std::string name;
    
    /// @brief Version
    std::string version;
    
    /// @brief Description
    std::string description;
    
    /// @brief Add-on path (XPI or folder)
    fs::path addonPath;
    
    /// @brief Profile name
    std::string profileName;
    
    /// @brief Add-on type
    AddonType type = AddonType::Unknown;
    
    /// @brief Source
    AddonSource source = AddonSource::Unknown;
    
    /// @brief Permissions
    std::vector<std::string> permissions;
    
    /// @brief Permission details
    std::vector<FirefoxPermissionInfo> permissionDetails;
    
    /// @brief Manifest
    FirefoxManifest manifest;
    
    /// @brief Signature info
    SignatureInfo signature;
    
    /// @brief Is sideloaded
    bool isSideloaded = false;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Is enabled
    bool isEnabled = true;
    
    /// @brief Is built-in
    bool isBuiltIn = false;
    
    /// @brief Installed time
    SystemTimePoint installedTime;
    
    /// @brief Last updated
    SystemTimePoint lastUpdated;
    
    /// @brief AMO URL
    std::string amoUrl;
    
    /// @brief XPI hash
    std::string xpiHash;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Add-on scan result
 */
struct AddonScanResult {
    /// @brief Add-on info
    FirefoxAddonInfo info;
    
    /// @brief Verdict
    AddonVerdict verdict = AddonVerdict::Unknown;
    
    /// @brief Risk level
    AddonRiskLevel riskLevel = AddonRiskLevel::None;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Code analysis
    AddonCodeAnalysis codeAnalysis;
    
    /// @brief Dangerous permissions count
    int dangerousPermissionsCount = 0;
    
    /// @brief Issues found
    std::vector<std::string> issues;
    
    /// @brief Recommendations
    std::vector<std::string> recommendations;
    
    /// @brief Threat intel matches
    std::vector<std::string> threatIntelMatches;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    [[nodiscard]] bool IsClean() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct FirefoxAddonScannerStatistics {
    std::atomic<uint64_t> totalScanned{0};
    std::atomic<uint64_t> safeFound{0};
    std::atomic<uint64_t> suspiciousFound{0};
    std::atomic<uint64_t> maliciousFound{0};
    std::atomic<uint64_t> unsignedFound{0};
    std::atomic<uint64_t> sideloadedFound{0};
    std::atomic<uint64_t> overPrivilegedFound{0};
    std::atomic<uint64_t> profilesScanned{0};
    std::atomic<uint64_t> xpisExtracted{0};
    std::atomic<uint64_t> jsFilesAnalyzed{0};
    std::atomic<uint64_t> obfuscatedFound{0};
    std::array<std::atomic<uint64_t>, 16> byVerdict{};
    std::array<std::atomic<uint64_t>, 8> byType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct FirefoxAddonScannerConfiguration {
    /// @brief Enable scanner
    bool enabled = true;
    
    /// @brief Scan type
    AddonScanType scanType = AddonScanType::Standard;
    
    /// @brief Analyze code
    bool analyzeCode = true;
    
    /// @brief Verify signatures
    bool verifySignatures = true;
    
    /// @brief Flag unsigned
    bool flagUnsigned = true;
    
    /// @brief Flag sideloaded
    bool flagSideloaded = true;
    
    /// @brief Check threat intel
    bool checkThreatIntel = true;
    
    /// @brief Check AMO
    bool checkAMO = false;
    
    /// @brief Block malicious
    bool blockMalicious = false;
    
    /// @brief Allowed add-on IDs
    std::vector<std::string> allowedAddonIds;
    
    /// @brief Blocked add-on IDs
    std::vector<std::string> blockedAddonIds;
    
    /// @brief Max XPI size
    size_t maxXpiSize = FirefoxAddonConstants::MAX_XPI_SIZE;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AddonScanResultCallback = std::function<void(const AddonScanResult&)>;
using MaliciousAddonCallback = std::function<void(const FirefoxAddonInfo&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// FIREFOX ADDON SCANNER CLASS
// ============================================================================

/**
 * @class FirefoxAddonScanner
 * @brief Enterprise Firefox add-on security scanner
 */
class FirefoxAddonScanner final {
public:
    [[nodiscard]] static FirefoxAddonScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    FirefoxAddonScanner(const FirefoxAddonScanner&) = delete;
    FirefoxAddonScanner& operator=(const FirefoxAddonScanner&) = delete;
    FirefoxAddonScanner(FirefoxAddonScanner&&) = delete;
    FirefoxAddonScanner& operator=(FirefoxAddonScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const FirefoxAddonScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const FirefoxAddonScannerConfiguration& config);
    [[nodiscard]] FirefoxAddonScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan all add-ons
    [[nodiscard]] std::vector<AddonScanResult> ScanAll();
    
    /// @brief Scan specific profile
    [[nodiscard]] std::vector<AddonScanResult> ScanProfile(const fs::path& profilePath);
    
    /// @brief Scan specific XPI file
    [[nodiscard]] AddonScanResult ScanXpi(const fs::path& xpiPath);
    
    /// @brief Scan add-on folder
    [[nodiscard]] AddonScanResult ScanAddonFolder(const fs::path& folderPath);
    
    /// @brief Get all installed add-ons
    [[nodiscard]] std::vector<FirefoxAddonInfo> GetInstalledAddons();
    
    /// @brief Get add-ons for profile
    [[nodiscard]] std::vector<FirefoxAddonInfo> GetAddonsForProfile(
        const fs::path& profilePath);

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Extract and analyze XPI
    [[nodiscard]] std::optional<FirefoxAddonInfo> ExtractAndAnalyzeXpi(
        const fs::path& xpiPath);
    
    /// @brief Analyze permissions
    [[nodiscard]] std::vector<FirefoxPermissionInfo> AnalyzePermissions(
        const std::vector<std::string>& permissions);
    
    /// @brief Analyze add-on code
    [[nodiscard]] AddonCodeAnalysis AnalyzeCode(const fs::path& addonPath);
    
    /// @brief Verify add-on signature
    [[nodiscard]] SignatureInfo VerifySignature(const fs::path& xpiPath);
    
    /// @brief Check if add-on is malicious
    [[nodiscard]] bool IsMalicious(const std::string& addonId);

    // ========================================================================
    // PROFILE DISCOVERY
    // ========================================================================
    
    /// @brief Get Firefox profiles
    [[nodiscard]] std::vector<fs::path> GetFirefoxProfiles();
    
    /// @brief Parse profiles.ini
    [[nodiscard]] std::vector<std::pair<std::string, fs::path>> ParseProfilesIni();

    // ========================================================================
    // POLICY
    // ========================================================================
    
    /// @brief Allow add-on
    [[nodiscard]] bool AllowAddon(const std::string& addonId);
    
    /// @brief Block add-on
    [[nodiscard]] bool BlockAddon(const std::string& addonId);
    
    /// @brief Is add-on allowed
    [[nodiscard]] bool IsAddonAllowed(const std::string& addonId) const;
    
    /// @brief Is add-on blocked
    [[nodiscard]] bool IsAddonBlocked(const std::string& addonId) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScanCallback(AddonScanResultCallback callback);
    void RegisterMaliciousCallback(MaliciousAddonCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] FirefoxAddonScannerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    FirefoxAddonScanner();
    ~FirefoxAddonScanner();
    
    std::unique_ptr<FirefoxAddonScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAddonVerdictName(AddonVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetAddonRiskLevelName(AddonRiskLevel level) noexcept;
[[nodiscard]] std::string_view GetAddonTypeName(AddonType type) noexcept;
[[nodiscard]] std::string_view GetAddonSourceName(AddonSource source) noexcept;
[[nodiscard]] std::string_view GetSignatureStatusName(SignatureStatus status) noexcept;

/// @brief Extract XPI archive
[[nodiscard]] bool ExtractXpi(const fs::path& xpiPath, const fs::path& destPath);

/// @brief Parse Firefox manifest.json
[[nodiscard]] std::optional<FirefoxManifest> ParseFirefoxManifest(const fs::path& manifestPath);

/// @brief Get Mozilla AMO URL
[[nodiscard]] std::string GetAMOUrl(const std::string& addonId);

/// @brief Is dangerous permission
[[nodiscard]] bool IsFirefoxDangerousPermission(const std::string& permission);

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_FIREFOX_ADDON_SCAN_ALL() \
    ::ShadowStrike::WebBrowser::FirefoxAddonScanner::Instance().ScanAll()

#define SS_FIREFOX_ADDON_IS_MALICIOUS(id) \
    ::ShadowStrike::WebBrowser::FirefoxAddonScanner::Instance().IsMalicious(id)

#define SS_FIREFOX_ADDON_BLOCK(id) \
    ::ShadowStrike::WebBrowser::FirefoxAddonScanner::Instance().BlockAddon(id)
