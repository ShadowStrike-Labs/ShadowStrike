/**
 * ============================================================================
 * ShadowStrike Banking Protection - SECURE BROWSER
 * ============================================================================
 *
 * @file SecureBrowser.hpp
 * @brief Enterprise-grade isolated secure browser environment for financial
 *        transactions and sensitive web operations.
 *
 * Provides a hardened, isolated browser session protected against all known
 * attack vectors used by banking trojans and credential-stealing malware.
 *
 * SECURITY FEATURES:
 * ==================
 *
 * 1. PROCESS ISOLATION
 *    - Restricted token creation
 *    - AppContainer sandboxing
 *    - Job object restrictions
 *    - Mandatory Integrity Level
 *    - DEP/ASLR enforcement
 *
 * 2. INJECTION PROTECTION
 *    - DLL injection blocking
 *    - Thread hijacking prevention
 *    - APC injection detection
 *    - SetWindowsHookEx blocking
 *    - Process hollowing detection
 *
 * 3. INPUT PROTECTION
 *    - Keylogger blocking
 *    - Secure keyboard input
 *    - Clipboard isolation
 *    - Virtual keyboard support
 *    - Screen capture blocking
 *
 * 4. NETWORK ISOLATION
 *    - Domain whitelist enforcement
 *    - SSL certificate pinning
 *    - Proxy/MITM detection
 *    - DNS security (DoH/DoT)
 *    - Traffic inspection
 *
 * 5. BROWSER HARDENING
 *    - Extension blocking
 *    - Plugin disabling
 *    - JavaScript restrictions
 *    - Developer tools blocking
 *    - Incognito/private mode
 *
 * 6. SESSION MANAGEMENT
 *    - Isolated profile
 *    - Cookie isolation
 *    - Cache clearing
 *    - History purge
 *    - Credential protection
 *
 * SUPPORTED BROWSERS:
 * ===================
 * - Google Chrome
 * - Microsoft Edge (Chromium)
 * - Mozilla Firefox
 * - Brave Browser
 * - Custom Chromium builds
 *
 * INTEGRATION:
 * ============
 * - Utils::ProcessUtils for process management
 * - CertificatePinning for SSL protection
 * - KeyloggerProtection for input security
 * - ScreenshotBlocker for visual protection
 *
 * @note Requires elevated privileges for full isolation.
 * @note Some features require Windows 10 1709+ for AppContainer.
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
#include "../Utils/FileUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Banking {
    class SecureBrowserImpl;
}

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SecureBrowserConstants {

    // ========================================================================
    // VERSION
    // ========================================================================

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================

    /// @brief Maximum concurrent sessions
    inline constexpr size_t MAX_CONCURRENT_SESSIONS = 4;

    /// @brief Maximum allowed domains
    inline constexpr size_t MAX_ALLOWED_DOMAINS = 256;

    /// @brief Maximum blocked DLLs
    inline constexpr size_t MAX_BLOCKED_DLLS = 512;

    /// @brief Maximum session duration (hours)
    inline constexpr uint32_t MAX_SESSION_DURATION_HOURS = 4;

    // ========================================================================
    // TIMING
    // ========================================================================

    /// @brief Integrity check interval (seconds)
    inline constexpr uint32_t INTEGRITY_CHECK_INTERVAL_SECS = 10;

    /// @brief Process monitor interval (ms)
    inline constexpr uint32_t PROCESS_MONITOR_INTERVAL_MS = 500;

    /// @brief Session timeout warning (minutes)
    inline constexpr uint32_t SESSION_TIMEOUT_WARNING_MINS = 5;

    // ========================================================================
    // BROWSER PATHS
    // ========================================================================

    /// @brief Default Chrome path patterns
    inline constexpr const wchar_t* CHROME_PATH_PATTERNS[] = {
        L"%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe",
        L"%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe",
        L"%LocalAppData%\\Google\\Chrome\\Application\\chrome.exe"
    };

    /// @brief Default Edge path
    inline constexpr const wchar_t* EDGE_PATH =
        L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe";

    /// @brief Default Firefox path
    inline constexpr const wchar_t* FIREFOX_PATH =
        L"%ProgramFiles%\\Mozilla Firefox\\firefox.exe";

}  // namespace SecureBrowserConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using ProcessId = uint32_t;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Browser type
 */
enum class BrowserType : uint8_t {
    Unknown     = 0,
    Chrome      = 1,    ///< Google Chrome
    Edge        = 2,    ///< Microsoft Edge (Chromium)
    Firefox     = 3,    ///< Mozilla Firefox
    Brave       = 4,    ///< Brave Browser
    Chromium    = 5,    ///< Chromium base
    Custom      = 6     ///< Custom browser
};

/**
 * @brief Security level
 */
enum class SecurityLevel : uint8_t {
    Standard    = 0,    ///< Basic extension blocking
    Enhanced    = 1,    ///< + Anti-hooking, Anti-screenshot
    High        = 2,    ///< + Network isolation, Process isolation
    Maximum     = 3,    ///< + AppContainer, Virtual desktop
    Paranoid    = 4     ///< All protections + kernel driver
};

/**
 * @brief Session status
 */
enum class SessionStatus : uint8_t {
    None            = 0,
    Initializing    = 1,
    Running         = 2,
    Protected       = 3,
    Compromised     = 4,
    Terminating     = 5,
    Terminated      = 6,
    Error           = 7
};

/**
 * @brief Integrity status
 */
enum class IntegrityStatus : uint8_t {
    Unknown         = 0,
    Verified        = 1,
    DLLInjected     = 2,
    HooksDetected   = 3,
    MemoryModified  = 4,
    ThreadHijacked  = 5,
    Compromised     = 6
};

/**
 * @brief Network isolation mode
 */
enum class NetworkIsolationMode : uint8_t {
    None            = 0,    ///< No network isolation
    DomainWhitelist = 1,    ///< Only allow whitelisted domains
    BankingOnly     = 2,    ///< Only banking/financial sites
    Full            = 3     ///< Complete network isolation
};

/**
 * @brief Security event type
 */
enum class SecurityEventType : uint8_t {
    None                = 0,
    SessionStarted      = 1,
    SessionEnded        = 2,
    InjectionBlocked    = 3,
    ScreenshotBlocked   = 4,
    KeyloggerBlocked    = 5,
    NetworkBlocked      = 6,
    IntegrityViolation  = 7,
    HookDetected        = 8,
    Compromised         = 9,
    DomainBlocked       = 10,
    CertificateWarning  = 11
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
 * @brief Browser session configuration
 */
struct BrowserSessionConfiguration {
    /// @brief Browser type
    BrowserType browserType = BrowserType::Chrome;

    /// @brief Custom executable path
    std::wstring executablePath;

    /// @brief Starting URL
    std::wstring startingUrl;

    /// @brief Security level
    SecurityLevel securityLevel = SecurityLevel::High;

    /// @brief Use private/incognito mode
    bool usePrivateMode = true;

    /// @brief Clear cache on exit
    bool clearCacheOnExit = true;

    /// @brief Clear cookies on exit
    bool clearCookiesOnExit = true;

    /// @brief Clear history on exit
    bool clearHistoryOnExit = true;

    /// @brief Disable extensions
    bool disableExtensions = true;

    /// @brief Disable plugins
    bool disablePlugins = true;

    /// @brief Disable developer tools
    bool disableDevTools = true;

    /// @brief Block downloads
    bool blockDownloads = false;

    /// @brief Network isolation mode
    NetworkIsolationMode networkIsolation = NetworkIsolationMode::None;

    /// @brief Allowed domains (for whitelist mode)
    std::vector<std::string> allowedDomains;

    /// @brief Use AppContainer
    bool useAppContainer = true;

    /// @brief Use virtual desktop
    bool useVirtualDesktop = false;

    /// @brief Enable keylogger protection
    bool enableKeyloggerProtection = true;

    /// @brief Enable screenshot protection
    bool enableScreenshotProtection = true;

    /// @brief Enable certificate pinning
    bool enableCertPinning = true;

    /// @brief Maximum session duration (seconds, 0 = unlimited)
    uint32_t maxSessionDurationSecs = 0;

    /// @brief Custom command line arguments
    std::vector<std::wstring> customArgs;

    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Session info
 */
struct BrowserSessionInfo {
    /// @brief Session ID
    std::string sessionId;

    /// @brief Browser type
    BrowserType browserType = BrowserType::Unknown;

    /// @brief Process ID
    ProcessId processId = 0;

    /// @brief Main window handle
    uint64_t mainWindowHandle = 0;

    /// @brief Session status
    SessionStatus status = SessionStatus::None;

    /// @brief Integrity status
    IntegrityStatus integrityStatus = IntegrityStatus::Unknown;

    /// @brief Security level
    SecurityLevel securityLevel = SecurityLevel::Standard;

    /// @brief Start time
    SystemTimePoint startTime;

    /// @brief Current URL
    std::wstring currentUrl;

    /// @brief Profile path
    std::wstring profilePath;

    /// @brief Is protected
    bool isProtected = false;

    /// @brief Is compromised
    bool isCompromised = false;

    /**
     * @brief Get session duration
     */
    [[nodiscard]] std::chrono::seconds GetDuration() const noexcept;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Security event
 */
struct SecurityEvent {
    /// @brief Event ID
    std::string eventId;

    /// @brief Session ID
    std::string sessionId;

    /// @brief Event type
    SecurityEventType eventType = SecurityEventType::None;

    /// @brief Source process ID
    ProcessId sourceProcessId = 0;

    /// @brief Source process name
    std::wstring sourceProcessName;

    /// @brief Description
    std::string description;

    /// @brief Additional details
    std::string details;

    /// @brief Was blocked
    bool wasBlocked = false;

    /// @brief Severity (1-5)
    uint8_t severity = 1;

    /// @brief Timestamp
    SystemTimePoint timestamp;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Loaded DLL info
 */
struct LoadedDLLInfo {
    /// @brief Module name
    std::wstring moduleName;

    /// @brief Full path
    std::wstring fullPath;

    /// @brief Base address
    uint64_t baseAddress = 0;

    /// @brief Size
    uint64_t size = 0;

    /// @brief Is signed
    bool isSigned = false;

    /// @brief Signer name
    std::wstring signerName;

    /// @brief Is system DLL
    bool isSystemDLL = false;

    /// @brief Is suspicious
    bool isSuspicious = false;

    /// @brief Load time
    SystemTimePoint loadTime;
};

/**
 * @brief Session statistics
 */
struct SessionStatistics {
    /// @brief Session duration
    std::chrono::seconds duration{0};

    /// @brief Blocked injections
    std::atomic<uint32_t> blockedInjections{0};

    /// @brief Blocked screenshots
    std::atomic<uint32_t> blockedScreenshots{0};

    /// @brief Blocked keyloggers
    std::atomic<uint32_t> blockedKeyloggers{0};

    /// @brief Blocked network requests
    std::atomic<uint32_t> blockedNetworkRequests{0};

    /// @brief Integrity checks passed
    std::atomic<uint32_t> integrityChecksPassed{0};

    /// @brief Integrity checks failed
    std::atomic<uint32_t> integrityChecksFailed{0};

    /// @brief Pages visited
    std::atomic<uint32_t> pagesVisited{0};

    /// @brief Was compromised
    bool wasCompromised = false;

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
 * @brief Module statistics
 */
struct SecureBrowserStatistics {
    /// @brief Total sessions
    std::atomic<uint64_t> totalSessions{0};

    /// @brief Active sessions
    std::atomic<uint64_t> activeSessions{0};

    /// @brief Total security events
    std::atomic<uint64_t> totalSecurityEvents{0};

    /// @brief Blocked injections
    std::atomic<uint64_t> blockedInjections{0};

    /// @brief Compromised sessions
    std::atomic<uint64_t> compromisedSessions{0};

    /// @brief Average session duration (seconds)
    std::atomic<uint64_t> avgSessionDurationSecs{0};

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
 * @brief Module configuration
 */
struct SecureBrowserConfiguration {
    /// @brief Default browser type
    BrowserType defaultBrowser = BrowserType::Chrome;

    /// @brief Default security level
    SecurityLevel defaultSecurityLevel = SecurityLevel::High;

    /// @brief Enable auto-protection
    bool enableAutoProtection = true;

    /// @brief Enable integrity monitoring
    bool enableIntegrityMonitoring = true;

    /// @brief Terminate on compromise
    bool terminateOnCompromise = true;

    /// @brief Banking domains list path
    std::wstring bankingDomainsPath;

    /// @brief Custom browser paths
    std::map<BrowserType, std::wstring> customBrowserPaths;

    /// @brief Blocked DLLs path
    std::wstring blockedDLLsPath;

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

/// @brief Security event callback
using SecurityEventCallback = std::function<void(const SecurityEvent&)>;

/// @brief Session status callback
using SessionStatusCallback = std::function<void(const BrowserSessionInfo&)>;

/// @brief Integrity check callback
using IntegrityCheckCallback = std::function<void(IntegrityStatus status, const std::string& details)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SECURE BROWSER CLASS
// ============================================================================

/**
 * @class SecureBrowser
 * @brief Enterprise-grade isolated secure browser environment
 *
 * Provides a hardened browser session for secure financial transactions,
 * protected against all known attack vectors.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& browser = SecureBrowser::Instance();
 *     browser.Initialize(config);
 *
 *     BrowserSessionConfiguration sessionConfig;
 *     sessionConfig.startingUrl = L"https://mybank.com";
 *     sessionConfig.securityLevel = SecurityLevel::High;
 *
 *     browser.LaunchSession(sessionConfig);
 * @endcode
 */
class SecureBrowser final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static SecureBrowser& Instance() noexcept;

    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    // Non-copyable, non-movable
    SecureBrowser(const SecureBrowser&) = delete;
    SecureBrowser& operator=(const SecureBrowser&) = delete;
    SecureBrowser(SecureBrowser&&) = delete;
    SecureBrowser& operator=(SecureBrowser&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize module
     */
    [[nodiscard]] bool Initialize(const SecureBrowserConfiguration& config = {});

    /**
     * @brief Shutdown module
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
    [[nodiscard]] bool UpdateConfiguration(const SecureBrowserConfiguration& config);

    /**
     * @brief Get current configuration
     */
    [[nodiscard]] SecureBrowserConfiguration GetConfiguration() const;

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Launch secure browser session
     */
    [[nodiscard]] std::optional<std::string> LaunchSession(
        const BrowserSessionConfiguration& config);

    /**
     * @brief End session by ID
     */
    void EndSession(const std::string& sessionId);

    /**
     * @brief End all sessions
     */
    void EndAllSessions();

    /**
     * @brief Check if session is active
     */
    [[nodiscard]] bool IsSessionActive(const std::string& sessionId) const;

    /**
     * @brief Get session info
     */
    [[nodiscard]] std::optional<BrowserSessionInfo> GetSessionInfo(
        const std::string& sessionId) const;

    /**
     * @brief Get active sessions
     */
    [[nodiscard]] std::vector<BrowserSessionInfo> GetActiveSessions() const;

    /**
     * @brief Get browser PID for session
     */
    [[nodiscard]] ProcessId GetBrowserPid(const std::string& sessionId) const;

    // ========================================================================
    // PROTECTION
    // ========================================================================

    /**
     * @brief Enable screen protection for session
     */
    [[nodiscard]] bool EnableScreenProtection(const std::string& sessionId);

    /**
     * @brief Enable keylogger protection for session
     */
    [[nodiscard]] bool EnableKeyloggerProtection(const std::string& sessionId);

    /**
     * @brief Enable injection protection for session
     */
    [[nodiscard]] bool EnableInjectionProtection(const std::string& sessionId);

    /**
     * @brief Enable all protections
     */
    [[nodiscard]] bool EnableAllProtections(const std::string& sessionId);

    // ========================================================================
    // INTEGRITY
    // ========================================================================

    /**
     * @brief Verify session integrity
     */
    [[nodiscard]] IntegrityStatus VerifyIntegrity(const std::string& sessionId);

    /**
     * @brief Get loaded DLLs for session
     */
    [[nodiscard]] std::vector<LoadedDLLInfo> GetLoadedDLLs(
        const std::string& sessionId) const;

    /**
     * @brief Check for suspicious DLLs
     */
    [[nodiscard]] std::vector<LoadedDLLInfo> CheckSuspiciousDLLs(
        const std::string& sessionId) const;

    // ========================================================================
    // BROWSER DETECTION
    // ========================================================================

    /**
     * @brief Detect installed browsers
     */
    [[nodiscard]] std::vector<BrowserType> DetectInstalledBrowsers() const;

    /**
     * @brief Get browser executable path
     */
    [[nodiscard]] std::wstring GetBrowserPath(BrowserType type) const;

    /**
     * @brief Check if browser is installed
     */
    [[nodiscard]] bool IsBrowserInstalled(BrowserType type) const;

    // ========================================================================
    // DOMAIN MANAGEMENT
    // ========================================================================

    /**
     * @brief Load banking domains
     */
    [[nodiscard]] bool LoadBankingDomains(const std::filesystem::path& path);

    /**
     * @brief Add allowed domain
     */
    void AddAllowedDomain(const std::string& sessionId, const std::string& domain);

    /**
     * @brief Remove allowed domain
     */
    void RemoveAllowedDomain(const std::string& sessionId, const std::string& domain);

    /**
     * @brief Check if domain is allowed
     */
    [[nodiscard]] bool IsDomainAllowed(const std::string& sessionId,
                                       const std::string& domain) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    /**
     * @brief Register security event callback
     */
    void RegisterSecurityEventCallback(SecurityEventCallback callback);

    /**
     * @brief Register session status callback
     */
    void RegisterSessionStatusCallback(SessionStatusCallback callback);

    /**
     * @brief Register integrity check callback
     */
    void RegisterIntegrityCheckCallback(IntegrityCheckCallback callback);

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
     * @brief Get module statistics
     */
    [[nodiscard]] SecureBrowserStatistics GetStatistics() const;

    /**
     * @brief Get session statistics
     */
    [[nodiscard]] std::optional<SessionStatistics> GetSessionStatistics(
        const std::string& sessionId) const;

    /**
     * @brief Reset statistics
     */
    void ResetStatistics();

    /**
     * @brief Get recent security events
     */
    [[nodiscard]] std::vector<SecurityEvent> GetRecentSecurityEvents(
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

    SecureBrowser();
    ~SecureBrowser();

    // ========================================================================
    // PIMPL
    // ========================================================================

    std::unique_ptr<SecureBrowserImpl> m_impl;

    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================

    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get browser type name
 */
[[nodiscard]] std::string_view GetBrowserTypeName(BrowserType type) noexcept;

/**
 * @brief Get security level name
 */
[[nodiscard]] std::string_view GetSecurityLevelName(SecurityLevel level) noexcept;

/**
 * @brief Get session status name
 */
[[nodiscard]] std::string_view GetSessionStatusName(SessionStatus status) noexcept;

/**
 * @brief Get integrity status name
 */
[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept;

/**
 * @brief Get security event type name
 */
[[nodiscard]] std::string_view GetSecurityEventTypeName(SecurityEventType type) noexcept;

/**
 * @brief Check if domain is banking domain
 */
[[nodiscard]] bool IsBankingDomain(std::string_view domain);

}  // namespace Banking
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Launch secure banking session
 */
#define SS_LAUNCH_SECURE_BROWSER(config) \
    ::ShadowStrike::Banking::SecureBrowser::Instance().LaunchSession(config)

/**
 * @brief End secure browser session
 */
#define SS_END_SECURE_BROWSER(sessionId) \
    ::ShadowStrike::Banking::SecureBrowser::Instance().EndSession(sessionId)
