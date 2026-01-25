/**
 * ============================================================================
 * ShadowStrike NGAV - OVERLAY PROTECTION MODULE
 * ============================================================================
 *
 * @file OverlayProtection.hpp
 * @brief Enterprise-grade overlay integrity protection ensuring secure
 *        rendering of security alerts over games and fullscreen applications.
 *
 * Protects the antivirus overlay from hijacking by malware and prevents
 * malicious DLLs from hooking graphics API swapchains.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. OVERLAY INTEGRITY
 *    - Secure window creation
 *    - Z-order protection
 *    - Message hook defense
 *    - HWND hijack prevention
 *    - DWM composition check
 *
 * 2. GRAPHICS API PROTECTION
 *    - DirectX hook detection
 *    - Vulkan hook detection
 *    - OpenGL hook detection
 *    - Present/SwapBuffers monitoring
 *    - Shader injection detection
 *
 * 3. DLL INJECTION DEFENSE
 *    - Module load monitoring
 *    - Import table validation
 *    - Inline hook detection
 *    - IAT/EAT manipulation
 *    - Known overlay DLLs
 *
 * 4. RENDERING SECURITY
 *    - Secure notification rendering
 *    - Alpha channel protection
 *    - Click-through handling
 *    - Multi-monitor support
 *    - DPI awareness
 *
 * 5. COMPATIBILITY
 *    - Game overlay whitelist
 *    - Discord/Steam overlay
 *    - NVIDIA/AMD overlays
 *    - Recording software
 *    - Accessibility tools
 *
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
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>

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
#include "../Utils/SystemUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::GameMode {
    class OverlayProtectionImpl;
}

namespace ShadowStrike {
namespace GameMode {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace OverlayConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Overlay window class name
    inline constexpr const wchar_t* OVERLAY_CLASS_NAME = L"ShadowStrikeOverlay";
    
    /// @brief Integrity check interval (ms)
    inline constexpr uint32_t INTEGRITY_CHECK_INTERVAL_MS = 1000;
    
    /// @brief Maximum overlay dimensions
    inline constexpr uint32_t MAX_OVERLAY_WIDTH = 800;
    inline constexpr uint32_t MAX_OVERLAY_HEIGHT = 600;

}  // namespace OverlayConstants

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
 * @brief Overlay type
 */
enum class OverlayType : uint8_t {
    Notification    = 0,    ///< Alert notification
    ThreatWarning   = 1,    ///< Threat warning
    ScanProgress    = 2,    ///< Scan progress
    StatusIndicator = 3,    ///< Status indicator
    Interactive     = 4,    ///< Interactive dialog
    Custom          = 5
};

/**
 * @brief Overlay position
 */
enum class OverlayPosition : uint8_t {
    TopLeft         = 0,
    TopCenter       = 1,
    TopRight        = 2,
    CenterLeft      = 3,
    Center          = 4,
    CenterRight     = 5,
    BottomLeft      = 6,
    BottomCenter    = 7,
    BottomRight     = 8,
    Custom          = 9
};

/**
 * @brief Hook type detected
 */
enum class HookType : uint8_t {
    None            = 0,
    InlineHook      = 1,
    IATHook         = 2,
    EATHook         = 3,
    VTableHook      = 4,
    DetourHook      = 5,
    SwapchainHook   = 6,
    MessageHook     = 7,
    Unknown         = 8
};

/**
 * @brief Graphics API
 */
enum class GraphicsAPI : uint8_t {
    Unknown         = 0,
    DirectX9        = 1,
    DirectX10       = 2,
    DirectX11       = 3,
    DirectX12       = 4,
    Vulkan          = 5,
    OpenGL          = 6,
    GDI             = 7
};

/**
 * @brief Threat level
 */
enum class OverlayThreatLevel : uint8_t {
    None            = 0,
    Low             = 1,
    Medium          = 2,
    High            = 3,
    Critical        = 4
};

/**
 * @brief Module status
 */
enum class OverlayProtectionStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Protected       = 3,
    Compromised     = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Overlay window info
 */
struct OverlayWindowInfo {
    /// @brief Window handle
    HWND hwnd = nullptr;
    
    /// @brief Overlay type
    OverlayType type = OverlayType::Notification;
    
    /// @brief Position
    OverlayPosition position = OverlayPosition::TopRight;
    
    /// @brief Custom X position
    int32_t customX = 0;
    
    /// @brief Custom Y position
    int32_t customY = 0;
    
    /// @brief Width
    uint32_t width = 400;
    
    /// @brief Height
    uint32_t height = 200;
    
    /// @brief Opacity (0-255)
    uint8_t opacity = 255;
    
    /// @brief Is visible
    bool isVisible = false;
    
    /// @brief Is click-through
    bool isClickThrough = false;
    
    /// @brief Is topmost
    bool isTopmost = true;
    
    /// @brief Target monitor
    int32_t targetMonitor = -1;  // -1 = primary
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Hook detection result
 */
struct HookDetectionResult {
    /// @brief Detection ID
    std::string detectionId;
    
    /// @brief Hook type
    HookType hookType = HookType::None;
    
    /// @brief Module name
    std::wstring moduleName;
    
    /// @brief Function name
    std::string functionName;
    
    /// @brief Original address
    uint64_t originalAddress = 0;
    
    /// @brief Hook address
    uint64_t hookAddress = 0;
    
    /// @brief Hook destination
    uint64_t hookDestination = 0;
    
    /// @brief Hooking module
    std::wstring hookingModule;
    
    /// @brief Threat level
    OverlayThreatLevel threatLevel = OverlayThreatLevel::None;
    
    /// @brief Is known overlay (e.g., Discord)
    bool isKnownOverlay = false;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Graphics API status
 */
struct GraphicsAPIStatus {
    /// @brief API type
    GraphicsAPI api = GraphicsAPI::Unknown;
    
    /// @brief Is hooked
    bool isHooked = false;
    
    /// @brief Hook count
    uint32_t hookCount = 0;
    
    /// @brief Known overlays active
    std::vector<std::string> knownOverlays;
    
    /// @brief Suspicious hooks
    std::vector<HookDetectionResult> suspiciousHooks;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Integrity status
 */
struct OverlayIntegrityStatus {
    /// @brief Is secure
    bool isSecure = true;
    
    /// @brief Window intact
    bool windowIntact = true;
    
    /// @brief Z-order correct
    bool zOrderCorrect = true;
    
    /// @brief No unauthorized hooks
    bool noUnauthorizedHooks = true;
    
    /// @brief DWM composition enabled
    bool dwmCompositionEnabled = true;
    
    /// @brief Threats detected
    std::vector<HookDetectionResult> threats;
    
    /// @brief Last check time
    TimePoint lastCheckTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Known overlay (whitelist)
 */
struct KnownOverlay {
    /// @brief Name
    std::string name;
    
    /// @brief Module names
    std::vector<std::wstring> moduleNames;
    
    /// @brief Publisher
    std::string publisher;
    
    /// @brief Is trusted
    bool isTrusted = false;
    
    /// @brief Description
    std::string description;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct OverlayStatistics {
    std::atomic<uint64_t> integrityChecks{0};
    std::atomic<uint64_t> integrityFailures{0};
    std::atomic<uint64_t> hooksDetected{0};
    std::atomic<uint64_t> hooksBlocked{0};
    std::atomic<uint64_t> overlaysShown{0};
    std::atomic<uint64_t> zOrderRestorations{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct OverlayProtectionConfiguration {
    /// @brief Enable protection
    bool enabled = true;
    
    /// @brief Enable hook detection
    bool enableHookDetection = true;
    
    /// @brief Enable Z-order protection
    bool enableZOrderProtection = true;
    
    /// @brief Enable message hook defense
    bool enableMessageHookDefense = true;
    
    /// @brief Auto-restore Z-order
    bool autoRestoreZOrder = true;
    
    /// @brief Integrity check interval (ms)
    uint32_t integrityCheckIntervalMs = OverlayConstants::INTEGRITY_CHECK_INTERVAL_MS;
    
    /// @brief Default overlay position
    OverlayPosition defaultPosition = OverlayPosition::TopRight;
    
    /// @brief Default opacity
    uint8_t defaultOpacity = 255;
    
    /// @brief Click-through by default
    bool defaultClickThrough = false;
    
    /// @brief Whitelist
    std::vector<std::wstring> moduleWhitelist;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using HookDetectedCallback = std::function<void(const HookDetectionResult&)>;
using IntegrityCallback = std::function<void(const OverlayIntegrityStatus&)>;
using OverlayEventCallback = std::function<void(const OverlayWindowInfo&, bool created)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// OVERLAY PROTECTION CLASS
// ============================================================================

/**
 * @class OverlayProtection
 * @brief Enterprise overlay security
 */
class OverlayProtection final {
public:
    [[nodiscard]] static OverlayProtection& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    OverlayProtection(const OverlayProtection&) = delete;
    OverlayProtection& operator=(const OverlayProtection&) = delete;
    OverlayProtection(OverlayProtection&&) = delete;
    OverlayProtection& operator=(OverlayProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const OverlayProtectionConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] OverlayProtectionStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const OverlayProtectionConfiguration& config);
    [[nodiscard]] OverlayProtectionConfiguration GetConfiguration() const;

    // ========================================================================
    // OVERLAY SECURITY
    // ========================================================================
    
    /// @brief Secure the overlay
    [[nodiscard]] bool SecureOverlay();
    
    /// @brief Create secure overlay window
    [[nodiscard]] HWND CreateSecureOverlay(
        OverlayType type,
        OverlayPosition position = OverlayPosition::TopRight,
        uint32_t width = 400,
        uint32_t height = 200);
    
    /// @brief Destroy overlay window
    void DestroyOverlay(HWND hwnd);
    
    /// @brief Show overlay
    void ShowOverlay(HWND hwnd);
    
    /// @brief Hide overlay
    void HideOverlay(HWND hwnd);
    
    /// @brief Set overlay content (custom rendering callback)
    void SetOverlayRenderer(HWND hwnd, std::function<void(HDC, RECT)> renderer);

    // ========================================================================
    // INTEGRITY CHECKING
    // ========================================================================
    
    /// @brief Check overlay integrity
    [[nodiscard]] OverlayIntegrityStatus CheckIntegrity();
    
    /// @brief Verify window not hijacked
    [[nodiscard]] bool VerifyWindowIntegrity(HWND hwnd);
    
    /// @brief Restore Z-order if needed
    [[nodiscard]] bool RestoreZOrder(HWND hwnd);
    
    /// @brief Start continuous integrity monitoring
    void StartIntegrityMonitoring();
    
    /// @brief Stop integrity monitoring
    void StopIntegrityMonitoring();

    // ========================================================================
    // HOOK DETECTION
    // ========================================================================
    
    /// @brief Scan for graphics hooks
    [[nodiscard]] std::vector<HookDetectionResult> ScanForHooks();
    
    /// @brief Get graphics API status
    [[nodiscard]] GraphicsAPIStatus GetGraphicsAPIStatus(GraphicsAPI api);
    
    /// @brief Get all graphics API statuses
    [[nodiscard]] std::vector<GraphicsAPIStatus> GetAllGraphicsAPIStatuses();
    
    /// @brief Is overlay DLL loaded
    [[nodiscard]] bool IsKnownOverlayLoaded(const std::wstring& moduleName);

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /// @brief Get known overlays
    [[nodiscard]] std::vector<KnownOverlay> GetKnownOverlays() const;
    
    /// @brief Add to whitelist
    [[nodiscard]] bool AddToWhitelist(const std::wstring& moduleName);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::wstring& moduleName);
    
    /// @brief Is whitelisted
    [[nodiscard]] bool IsWhitelisted(const std::wstring& moduleName) const;

    // ========================================================================
    // WINDOW MANAGEMENT
    // ========================================================================
    
    /// @brief Get overlay windows
    [[nodiscard]] std::vector<OverlayWindowInfo> GetOverlayWindows() const;
    
    /// @brief Get overlay info
    [[nodiscard]] std::optional<OverlayWindowInfo> GetOverlayInfo(HWND hwnd) const;
    
    /// @brief Set overlay position
    void SetOverlayPosition(HWND hwnd, OverlayPosition position);
    
    /// @brief Set overlay opacity
    void SetOverlayOpacity(HWND hwnd, uint8_t opacity);
    
    /// @brief Set click-through
    void SetClickThrough(HWND hwnd, bool enabled);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterHookDetectedCallback(HookDetectedCallback callback);
    void RegisterIntegrityCallback(IntegrityCallback callback);
    void RegisterOverlayEventCallback(OverlayEventCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] OverlayStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    OverlayProtection();
    ~OverlayProtection();
    
    std::unique_ptr<OverlayProtectionImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetOverlayTypeName(OverlayType type) noexcept;
[[nodiscard]] std::string_view GetOverlayPositionName(OverlayPosition position) noexcept;
[[nodiscard]] std::string_view GetHookTypeName(HookType type) noexcept;
[[nodiscard]] std::string_view GetGraphicsAPIName(GraphicsAPI api) noexcept;
[[nodiscard]] std::string_view GetThreatLevelName(OverlayThreatLevel level) noexcept;

/// @brief Calculate overlay position coordinates
[[nodiscard]] RECT CalculateOverlayPosition(
    OverlayPosition position,
    uint32_t width,
    uint32_t height,
    int32_t monitorIndex = -1);

/// @brief Detect active graphics API
[[nodiscard]] GraphicsAPI DetectActiveGraphicsAPI(uint32_t pid);

}  // namespace GameMode
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SECURE_OVERLAY() \
    ::ShadowStrike::GameMode::OverlayProtection::Instance().SecureOverlay()

#define SS_CHECK_OVERLAY_INTEGRITY() \
    ::ShadowStrike::GameMode::OverlayProtection::Instance().CheckIntegrity()
