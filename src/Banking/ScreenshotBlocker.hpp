#pragma once

/**
 * ============================================================================
 * ShadowStrike Banking Protection - SCREENSHOT BLOCKER
 * ============================================================================
 *
 * @file ScreenshotBlocker.hpp
 * @brief Enterprise-grade screen capture prevention for protecting sensitive
 *        financial information from visual credential theft.
 *
 * Implements comprehensive defenses against all known screen capture vectors
 * used by banking trojans and credential-stealing malware.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. WINDOW PROTECTION
 *    - SetWindowDisplayAffinity (WDA_EXCLUDEFROMCAPTURE)
 *    - Window content masking
 *    - Layered window protection
 *    - Z-order manipulation
 *
 * 2. API HOOK PROTECTION
 *    - BitBlt/StretchBlt/PatBlt hooks
 *    - GetDC/GetWindowDC interception
 *    - PrintWindow blocking
 *    - CreateDC protection
 *
 * 3. DIRECTX PROTECTION
 *    - DXGI Desktop Duplication blocking
 *    - D3D GetFrontBufferData hooks
 *    - Present call monitoring
 *    - Swapchain capture prevention
 *
 * 4. CAPTURE METHOD BLOCKING
 *    - PrintScreen key interception
 *    - Snipping Tool detection
 *    - Windows Game Bar blocking
 *    - Third-party screen recorders
 *    - Remote desktop capture
 *    - VNC/TeamViewer protection
 *
 * 5. CLIPBOARD PROTECTION
 *    - Screenshot clipboard filtering
 *    - Image content sanitization
 *    - Automatic clipboard clear
 *    - Copy operation monitoring
 *
 * 6. MAGNIFICATION API
 *    - Magnifier abuse detection
 *    - Magnification callback hooks
 *    - Screen reader whitelisting
 *
 * INTEGRATION:
 * ============
 * - Utils::ProcessUtils for process identification
 * - Utils::RegistryUtils for configuration
 * - Whitelist for accessibility tools
 *
 * @note Requires elevated privileges for full API hook coverage.
 * @note SetWindowDisplayAffinity available Windows 7+, enhanced Win10 2004+.
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
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Banking {
    class ScreenshotBlockerImpl;
}

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ScreenshotConstants {

    // ========================================================================
    // VERSION
    // ========================================================================

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // WINDOWS DISPLAY AFFINITY FLAGS
    // ========================================================================

    /// @brief No display affinity
    inline constexpr uint32_t WDA_NONE = 0x00000000;

    /// @brief Exclude from monitor (legacy)
    inline constexpr uint32_t WDA_MONITOR = 0x00000001;

    /// @brief Exclude from capture (Windows 10 2004+)
    inline constexpr uint32_t WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    // ========================================================================
    // LIMITS
    // ========================================================================

    /// @brief Maximum protected windows
    inline constexpr size_t MAX_PROTECTED_WINDOWS = 256;

    /// @brief Maximum capture event history
    inline constexpr size_t MAX_CAPTURE_HISTORY = 1024;

    /// @brief Maximum whitelisted apps
    inline constexpr size_t MAX_WHITELISTED_APPS = 128;

    // ========================================================================
    // TIMING
    // ========================================================================

    /// @brief Capture detection scan interval (ms)
    inline constexpr uint32_t CAPTURE_SCAN_INTERVAL_MS = 100;

    /// @brief Clipboard sanitize delay (ms)
    inline constexpr uint32_t CLIPBOARD_SANITIZE_DELAY_MS = 50;

    /// @brief Protection timeout (ms)
    inline constexpr uint32_t PROTECTION_TIMEOUT_MS = 5000;

}  // namespace ScreenshotConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using WindowHandle = uint64_t;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Screenshot blocking method
 */
enum class BlockingMethod : uint8_t {
    None                    = 0,
    DisplayAffinity         = 1,    ///< SetWindowDisplayAffinity
    GDIHooks                = 2,    ///< Hook GDI capture functions
    DirectXHooks            = 3,    ///< Hook DirectX capture
    OverlayObfuscation      = 4,    ///< Black overlay window
    ClipboardFilter         = 5,    ///< Filter clipboard images
    Combined                = 6     ///< All methods combined
};

/**
 * @brief Capture attempt type
 */
enum class CaptureAttemptType : uint8_t {
    Unknown                 = 0,
    PrintScreenKey          = 1,    ///< PrtSc key press
    AltPrintScreen          = 2,    ///< Alt+PrtSc
    SnippingTool            = 3,    ///< Windows Snipping Tool
    SnipAndSketch           = 4,    ///< Windows Snip & Sketch
    GameBar                 = 5,    ///< Xbox Game Bar
    BitBltCapture           = 6,    ///< BitBlt API call
    StretchBltCapture       = 7,    ///< StretchBlt API call
    PrintWindow             = 8,    ///< PrintWindow API
    DesktopDuplication      = 9,    ///< DXGI Desktop Dup
    GetFrontBuffer          = 10,   ///< D3D front buffer
    ThirdPartyRecorder      = 11,   ///< OBS, Camtasia, etc.
    RemoteDesktop           = 12,   ///< RDP capture
    VNCCapture              = 13,   ///< VNC client
    TeamViewerCapture       = 14,   ///< TeamViewer
    MagnifierAbuse          = 15,   ///< Magnification API
    ClipboardCopy           = 16,   ///< Clipboard capture
    MalwareCapture          = 17    ///< Identified malware
};

/**
 * @brief Protection status
 */
enum class ProtectionStatus : uint8_t {
    Unprotected             = 0,
    Protected               = 1,
    ProtectionFailed        = 2,
    PartialProtection       = 3
};

/**
 * @brief Blocking result
 */
enum class BlockingResult : uint8_t {
    Success                 = 0,
    Failed                  = 1,
    NotSupported            = 2,
    Whitelisted             = 3,
    Timeout                 = 4
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized           = 0,
    Initializing            = 1,
    Running                 = 2,
    Paused                  = 3,
    Stopping                = 4,
    Stopped                 = 5,
    Error                   = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Protected window info
 */
struct ProtectedWindowInfo {
    /// @brief Window handle
    WindowHandle hwnd = 0;

    /// @brief Process ID
    uint32_t processId = 0;

    /// @brief Process name
    std::wstring processName;

    /// @brief Window title
    std::wstring windowTitle;

    /// @brief Window class
    std::wstring windowClass;

    /// @brief Protection status
    ProtectionStatus status = ProtectionStatus::Unprotected;

    /// @brief Blocking methods applied
    std::vector<BlockingMethod> appliedMethods;

    /// @brief Protection start time
    SystemTimePoint protectionStartTime;

    /// @brief Is currently visible
    bool isVisible = false;

    /// @brief Is minimized
    bool isMinimized = false;

    /// @brief Has focus
    bool hasFocus = false;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Capture attempt event
 */
struct CaptureAttemptEvent {
    /// @brief Event ID
    std::string eventId;

    /// @brief Capture type
    CaptureAttemptType captureType = CaptureAttemptType::Unknown;

    /// @brief Source process ID
    uint32_t sourceProcessId = 0;

    /// @brief Source process name
    std::wstring sourceProcessName;

    /// @brief Source process path
    std::wstring sourceProcessPath;

    /// @brief Target window handle
    WindowHandle targetHwnd = 0;

    /// @brief Target window title
    std::wstring targetWindowTitle;

    /// @brief Was blocked
    bool wasBlocked = false;

    /// @brief Blocking result
    BlockingResult blockingResult = BlockingResult::Failed;

    /// @brief Blocking method used
    BlockingMethod methodUsed = BlockingMethod::None;

    /// @brief Is whitelisted application
    bool isWhitelisted = false;

    /// @brief Whitelist reason
    std::string whitelistReason;

    /// @brief Timestamp
    SystemTimePoint timestamp;

    /// @brief Additional details
    std::string details;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief API hook info
 */
struct CaptureAPIHook {
    /// @brief Module name
    std::wstring moduleName;

    /// @brief Function name
    std::string functionName;

    /// @brief Original address
    uint64_t originalAddress = 0;

    /// @brief Hook address
    uint64_t hookAddress = 0;

    /// @brief Is installed
    bool isInstalled = false;

    /// @brief Calls intercepted
    std::atomic<uint64_t> callsIntercepted{0};
};

/**
 * @brief Blocker statistics
 */
struct ScreenshotBlockerStatistics {
    /// @brief Total protected windows
    std::atomic<uint64_t> totalProtectedWindows{0};

    /// @brief Currently protected windows
    std::atomic<uint64_t> currentlyProtected{0};

    /// @brief Capture attempts detected
    std::atomic<uint64_t> captureAttemptsDetected{0};

    /// @brief Capture attempts blocked
    std::atomic<uint64_t> captureAttemptsBlocked{0};

    /// @brief Clipboard events filtered
    std::atomic<uint64_t> clipboardEventsFiltered{0};

    /// @brief GDI calls intercepted
    std::atomic<uint64_t> gdiCallsIntercepted{0};

    /// @brief DirectX calls intercepted
    std::atomic<uint64_t> dxCallsIntercepted{0};

    /// @brief Whitelisted passes
    std::atomic<uint64_t> whitelistedPasses{0};

    /// @brief By capture type
    std::array<std::atomic<uint64_t>, 32> byCaptureType{};

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
struct ScreenshotBlockerConfiguration {
    /// @brief Enable display affinity protection
    bool enableDisplayAffinity = true;

    /// @brief Enable GDI hook protection
    bool enableGDIHooks = true;

    /// @brief Enable DirectX hook protection
    bool enableDirectXHooks = true;

    /// @brief Enable clipboard filtering
    bool enableClipboardFiltering = true;

    /// @brief Enable PrintScreen blocking
    bool enablePrintScreenBlocking = true;

    /// @brief Enable overlay obfuscation (fallback)
    bool enableOverlayObfuscation = false;

    /// @brief Use WDA_EXCLUDEFROMCAPTURE if available
    bool useEnhancedAffinity = true;

    /// @brief Auto-sanitize clipboard on capture attempt
    bool autoSanitizeClipboard = true;

    /// @brief Protect all password fields automatically
    bool autoProtectPasswordFields = true;

    /// @brief Allow screen readers (accessibility)
    bool allowAccessibilityTools = true;

    /// @brief Whitelisted applications
    std::vector<std::wstring> whitelistedApplications;

    /// @brief Whitelisted process names
    std::vector<std::wstring> whitelistedProcessNames;

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

/// @brief Capture attempt callback
using CaptureAttemptCallback = std::function<void(const CaptureAttemptEvent&)>;

/// @brief Window protection callback
using WindowProtectionCallback = std::function<void(const ProtectedWindowInfo&, bool protected_)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SCREENSHOT BLOCKER CLASS
// ============================================================================

/**
 * @class ScreenshotBlocker
 * @brief Enterprise-grade screen capture prevention engine
 *
 * Provides comprehensive protection against visual credential theft
 * by blocking all known screen capture methods.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& blocker = ScreenshotBlocker::Instance();
 *     blocker.Initialize(config);
 *
 *     // Protect specific window
 *     blocker.ProtectWindow(hwnd);
 * @endcode
 */
class ScreenshotBlocker final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static ScreenshotBlocker& Instance() noexcept;

    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    // Non-copyable, non-movable
    ScreenshotBlocker(const ScreenshotBlocker&) = delete;
    ScreenshotBlocker& operator=(const ScreenshotBlocker&) = delete;
    ScreenshotBlocker(ScreenshotBlocker&&) = delete;
    ScreenshotBlocker& operator=(ScreenshotBlocker&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize blocker
     */
    [[nodiscard]] bool Initialize(const ScreenshotBlockerConfiguration& config = {});

    /**
     * @brief Shutdown blocker
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
     * @brief Start protection
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Stop protection
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
    [[nodiscard]] bool UpdateConfiguration(const ScreenshotBlockerConfiguration& config);

    /**
     * @brief Get current configuration
     */
    [[nodiscard]] ScreenshotBlockerConfiguration GetConfiguration() const;

    // ========================================================================
    // WINDOW PROTECTION
    // ========================================================================

    /**
     * @brief Protect window from capture
     */
    [[nodiscard]] bool ProtectWindow(WindowHandle hwnd);

    /**
     * @brief Protect window with specific method
     */
    [[nodiscard]] bool ProtectWindow(WindowHandle hwnd, BlockingMethod method);

    /**
     * @brief Unprotect window
     */
    [[nodiscard]] bool UnprotectWindow(WindowHandle hwnd);

    /**
     * @brief Check if window is protected
     */
    [[nodiscard]] bool IsWindowProtected(WindowHandle hwnd) const;

    /**
     * @brief Get protection status
     */
    [[nodiscard]] ProtectionStatus GetWindowProtectionStatus(WindowHandle hwnd) const;

    /**
     * @brief Get protected window info
     */
    [[nodiscard]] std::optional<ProtectedWindowInfo> GetProtectedWindowInfo(
        WindowHandle hwnd) const;

    /**
     * @brief Get all protected windows
     */
    [[nodiscard]] std::vector<ProtectedWindowInfo> GetProtectedWindows() const;

    /**
     * @brief Protect all windows of process
     */
    [[nodiscard]] size_t ProtectProcessWindows(uint32_t processId);

    /**
     * @brief Auto-detect and protect password fields
     */
    void AutoProtectPasswordFields();

    // ========================================================================
    // CAPTURE BLOCKING
    // ========================================================================

    /**
     * @brief Block PrintScreen key
     */
    void BlockPrintScreen(bool block);

    /**
     * @brief Check if PrintScreen is blocked
     */
    [[nodiscard]] bool IsPrintScreenBlocked() const noexcept;

    /**
     * @brief Block specific capture application
     */
    void BlockCaptureApplication(std::wstring_view processName);

    /**
     * @brief Unblock capture application
     */
    void UnblockCaptureApplication(std::wstring_view processName);

    /**
     * @brief Check if application is blocked
     */
    [[nodiscard]] bool IsCaptureApplicationBlocked(std::wstring_view processName) const;

    // ========================================================================
    // CLIPBOARD PROTECTION
    // ========================================================================

    /**
     * @brief Enable clipboard filtering
     */
    void EnableClipboardFiltering(bool enable);

    /**
     * @brief Check if clipboard filtering status
     */
    [[nodiscard]] bool IsClipboardFilteringEnabled() const noexcept;

    /**
     * @brief Sanitize clipboard (clear if contains screenshot)
     */
    void SanitizeClipboard();

    /**
     * @brief Clear clipboard
     */
    void ClearClipboard();

    // ========================================================================
    // CAPABILITY CHECKS
    // ========================================================================

    /**
     * @brief Check if advanced protection available
     */
    [[nodiscard]] bool IsAdvancedProtectionAvailable() const noexcept;

    /**
     * @brief Check if WDA_EXCLUDEFROMCAPTURE supported
     */
    [[nodiscard]] bool IsExcludeFromCaptureSupported() const noexcept;

    /**
     * @brief Get supported blocking methods
     */
    [[nodiscard]] std::vector<BlockingMethod> GetSupportedMethods() const;

    // ========================================================================
    // WHITELIST
    // ========================================================================

    /**
     * @brief Add application to whitelist
     */
    void WhitelistApplication(const std::wstring& path, const std::string& reason);

    /**
     * @brief Add process to whitelist
     */
    void WhitelistProcess(const std::wstring& processName, const std::string& reason);

    /**
     * @brief Remove from whitelist
     */
    void RemoveFromWhitelist(const std::wstring& processName);

    /**
     * @brief Check if whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;

    /**
     * @brief Load accessibility tools whitelist
     */
    void LoadAccessibilityWhitelist();

    // ========================================================================
    // HOOKS
    // ========================================================================

    /**
     * @brief Install GDI capture hooks
     */
    [[nodiscard]] bool InstallGDIHooks();

    /**
     * @brief Uninstall GDI hooks
     */
    void UninstallGDIHooks();

    /**
     * @brief Install DirectX capture hooks
     */
    [[nodiscard]] bool InstallDirectXHooks();

    /**
     * @brief Uninstall DirectX hooks
     */
    void UninstallDirectXHooks();

    /**
     * @brief Get installed hooks
     */
    [[nodiscard]] std::vector<CaptureAPIHook> GetInstalledHooks() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    /**
     * @brief Register capture attempt callback
     */
    void RegisterCaptureAttemptCallback(CaptureAttemptCallback callback);

    /**
     * @brief Register window protection callback
     */
    void RegisterWindowProtectionCallback(WindowProtectionCallback callback);

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
    [[nodiscard]] ScreenshotBlockerStatistics GetStatistics() const;

    /**
     * @brief Reset statistics
     */
    void ResetStatistics();

    /**
     * @brief Get recent capture attempts
     */
    [[nodiscard]] std::vector<CaptureAttemptEvent> GetRecentCaptureAttempts(
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

    ScreenshotBlocker();
    ~ScreenshotBlocker();

    // ========================================================================
    // PIMPL
    // ========================================================================

    std::unique_ptr<ScreenshotBlockerImpl> m_impl;

    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================

    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get blocking method name
 */
[[nodiscard]] std::string_view GetBlockingMethodName(BlockingMethod method) noexcept;

/**
 * @brief Get capture attempt type name
 */
[[nodiscard]] std::string_view GetCaptureAttemptTypeName(CaptureAttemptType type) noexcept;

/**
 * @brief Get protection status name
 */
[[nodiscard]] std::string_view GetProtectionStatusName(ProtectionStatus status) noexcept;

/**
 * @brief Get blocking result name
 */
[[nodiscard]] std::string_view GetBlockingResultName(BlockingResult result) noexcept;

/**
 * @brief Check if process is known screen recorder
 */
[[nodiscard]] bool IsKnownScreenRecorder(std::wstring_view processName);

/**
 * @brief Check if process is accessibility tool
 */
[[nodiscard]] bool IsAccessibilityTool(std::wstring_view processName);

}  // namespace Banking
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Protect window from screenshots
 */
#define SS_PROTECT_WINDOW(hwnd) \
    ::ShadowStrike::Banking::ScreenshotBlocker::Instance().ProtectWindow( \
        reinterpret_cast<::ShadowStrike::Banking::WindowHandle>(hwnd))

/**
 * @brief Unprotect window
 */
#define SS_UNPROTECT_WINDOW(hwnd) \
    ::ShadowStrike::Banking::ScreenshotBlocker::Instance().UnprotectWindow( \
        reinterpret_cast<::ShadowStrike::Banking::WindowHandle>(hwnd))
