/**
 * ============================================================================
 * ShadowStrike NGAV - GAME PROCESS DETECTOR MODULE
 * ============================================================================
 *
 * @file GameProcessDetector.hpp
 * @brief Enterprise-grade game process identification with launcher detection,
 *        fullscreen monitoring, VR support, and extensive game database.
 *
 * Provides comprehensive game detection including process monitoring, launcher
 * tracking, fullscreen state detection, and VR application identification.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. PROCESS DETECTION
 *    - Known game database
 *    - Process name matching
 *    - Window title analysis
 *    - Parent process chain
 *    - Digital signature check
 *
 * 2. LAUNCHER DETECTION
 *    - Steam
 *    - Epic Games
 *    - Origin/EA
 *    - GOG Galaxy
 *    - Battle.net
 *    - Ubisoft Connect
 *    - Xbox Game Pass
 *    - Amazon Games
 *    - Riot Client
 *    - Custom launchers
 *
 * 3. FULLSCREEN DETECTION
 *    - Exclusive fullscreen
 *    - Borderless windowed
 *    - Multi-monitor support
 *    - HDR detection
 *    - Variable refresh rate
 *
 * 4. VR DETECTION
 *    - SteamVR
 *    - Oculus Runtime
 *    - Windows Mixed Reality
 *    - OpenXR applications
 *
 * 5. STREAMING DETECTION
 *    - OBS Studio
 *    - NVIDIA ShadowPlay
 *    - AMD ReLive
 *    - Windows Game Bar
 *    - Discord streaming
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
#include <unordered_set>
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
#include "../Utils/StringUtils.hpp"
#include "../PatternStore/PatternStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::GameMode {
    class GameProcessDetectorImpl;
}

namespace ShadowStrike {
namespace GameMode {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DetectorConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default poll interval (ms)
    inline constexpr uint32_t DEFAULT_POLL_INTERVAL_MS = 2000;
    
    /// @brief Database path
    inline constexpr const wchar_t* GAME_DATABASE_PATH = L"Data\\games.db";
    
    /// @brief Maximum tracked processes
    inline constexpr size_t MAX_TRACKED_PROCESSES = 100;
    
    /// @brief Fullscreen check cooldown (ms)
    inline constexpr uint32_t FULLSCREEN_CHECK_COOLDOWN_MS = 500;

}  // namespace DetectorConstants

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
 * @brief Game category
 */
enum class GameCategory : uint8_t {
    Unknown         = 0,
    AAA             = 1,    ///< AAA titles
    Indie           = 2,    ///< Indie games
    FreeToPlay      = 3,    ///< F2P games
    Emulator        = 4,    ///< Console emulators
    VR              = 5,    ///< VR games
    Casual          = 6,    ///< Casual games
    Browser         = 7     ///< Browser games
};

/**
 * @brief Launcher type
 */
enum class LauncherType : uint8_t {
    Unknown         = 0,
    Steam           = 1,
    Epic            = 2,
    Origin          = 3,
    GOG             = 4,
    Battlenet       = 5,
    Ubisoft         = 6,
    Xbox            = 7,
    Amazon          = 8,
    RiotClient      = 9,
    Rockstar        = 10,
    Bethesda        = 11,
    Custom          = 12
};

/**
 * @brief Window state
 */
enum class WindowState : uint8_t {
    Unknown         = 0,
    Windowed        = 1,
    BorderlessWindowed = 2,
    ExclusiveFullscreen = 3,
    Minimized       = 4
};

/**
 * @brief Detection method
 */
enum class DetectionMethod : uint8_t {
    ProcessName     = 0,
    WindowTitle     = 1,
    ParentProcess   = 2,
    DigitalSignature = 3,
    DirectoryPath   = 4,
    RegistryKey     = 5,
    WindowClass     = 6,
    Heuristic       = 7
};

/**
 * @brief VR platform
 */
enum class VRPlatform : uint8_t {
    None            = 0,
    SteamVR         = 1,
    OculusRuntime   = 2,
    WindowsMR       = 3,
    OpenXR          = 4
};

/**
 * @brief Module status
 */
enum class DetectorStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Monitoring      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Game entry in database
 */
struct GameEntry {
    /// @brief Game ID
    uint64_t gameId = 0;
    
    /// @brief Game title
    std::string title;
    
    /// @brief Executable names
    std::vector<std::wstring> executableNames;
    
    /// @brief Window class names
    std::vector<std::string> windowClasses;
    
    /// @brief Publisher
    std::string publisher;
    
    /// @brief Category
    GameCategory category = GameCategory::Unknown;
    
    /// @brief Launcher
    LauncherType launcher = LauncherType::Unknown;
    
    /// @brief Is VR game
    bool isVR = false;
    
    /// @brief Requires elevated performance
    bool requiresElevatedPerformance = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detected game process
 */
struct DetectedGame {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Executable path
    std::wstring executablePath;
    
    /// @brief Window handle
    HWND windowHandle = nullptr;
    
    /// @brief Window title
    std::string windowTitle;
    
    /// @brief Game entry (if matched)
    std::optional<GameEntry> gameEntry;
    
    /// @brief Detection method
    DetectionMethod detectionMethod = DetectionMethod::ProcessName;
    
    /// @brief Window state
    WindowState windowState = WindowState::Unknown;
    
    /// @brief Launcher type
    LauncherType launcherType = LauncherType::Unknown;
    
    /// @brief Detected time
    SystemTimePoint detectedTime;
    
    /// @brief Last activity time
    TimePoint lastActivityTime;
    
    /// @brief Is foreground
    bool isForeground = false;
    
    /// @brief Is fullscreen
    bool isFullscreen = false;
    
    /// @brief Confidence (0-100)
    uint8_t confidence = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Launcher info
 */
struct LauncherInfo {
    /// @brief Launcher type
    LauncherType type = LauncherType::Unknown;
    
    /// @brief Display name
    std::string displayName;
    
    /// @brief Process names
    std::vector<std::wstring> processNames;
    
    /// @brief Install path
    std::wstring installPath;
    
    /// @brief Is running
    bool isRunning = false;
    
    /// @brief Running PIDs
    std::vector<uint32_t> runningPids;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Fullscreen info
 */
struct FullscreenInfo {
    /// @brief Has fullscreen app
    bool hasFullscreenApp = false;
    
    /// @brief Window handle
    HWND windowHandle = nullptr;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Window state
    WindowState windowState = WindowState::Unknown;
    
    /// @brief Monitor handle
    HMONITOR monitorHandle = nullptr;
    
    /// @brief Monitor index
    int monitorIndex = 0;
    
    /// @brief Resolution width
    uint32_t resolutionWidth = 0;
    
    /// @brief Resolution height
    uint32_t resolutionHeight = 0;
    
    /// @brief Refresh rate
    uint32_t refreshRate = 0;
    
    /// @brief Is HDR active
    bool isHDRActive = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct DetectorStatistics {
    std::atomic<uint64_t> gamesDetected{0};
    std::atomic<uint64_t> fullscreenDetections{0};
    std::atomic<uint64_t> launcherDetections{0};
    std::atomic<uint64_t> vrDetections{0};
    std::atomic<uint64_t> falsePositives{0};
    std::atomic<uint64_t> processesScanned{0};
    std::atomic<uint64_t> databaseLookups{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct DetectorConfiguration {
    /// @brief Enable detection
    bool enabled = true;
    
    /// @brief Poll interval (ms)
    uint32_t pollIntervalMs = DetectorConstants::DEFAULT_POLL_INTERVAL_MS;
    
    /// @brief Enable fullscreen detection
    bool enableFullscreenDetection = true;
    
    /// @brief Enable launcher detection
    bool enableLauncherDetection = true;
    
    /// @brief Enable VR detection
    bool enableVRDetection = true;
    
    /// @brief Enable streaming detection
    bool enableStreamingDetection = true;
    
    /// @brief Use heuristics
    bool useHeuristics = true;
    
    /// @brief Minimum confidence threshold (0-100)
    uint8_t confidenceThreshold = 70;
    
    /// @brief Custom game database path
    std::wstring customDatabasePath;
    
    /// @brief User-defined games
    std::vector<std::wstring> userDefinedGames;
    
    /// @brief Excluded processes
    std::vector<std::wstring> excludedProcesses;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using GameDetectedCallback = std::function<void(const DetectedGame&)>;
using GameExitedCallback = std::function<void(uint32_t pid)>;
using FullscreenChangeCallback = std::function<void(bool isFullscreen, const FullscreenInfo&)>;
using LauncherCallback = std::function<void(LauncherType, bool isRunning)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// GAME PROCESS DETECTOR CLASS
// ============================================================================

/**
 * @class GameProcessDetector
 * @brief Enterprise game process detection
 */
class GameProcessDetector final {
public:
    [[nodiscard]] static GameProcessDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    GameProcessDetector(const GameProcessDetector&) = delete;
    GameProcessDetector& operator=(const GameProcessDetector&) = delete;
    GameProcessDetector(GameProcessDetector&&) = delete;
    GameProcessDetector& operator=(GameProcessDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const DetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] DetectorStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const DetectorConfiguration& config);
    [[nodiscard]] DetectorConfiguration GetConfiguration() const;

    // ========================================================================
    // GAME DETECTION
    // ========================================================================
    
    /// @brief Check if process is a game
    [[nodiscard]] bool IsGameProcess(uint32_t pid);
    
    /// @brief Check if process name is a known game
    [[nodiscard]] bool IsKnownGame(const std::wstring& processName);
    
    /// @brief Detect game from process
    [[nodiscard]] std::optional<DetectedGame> DetectGame(uint32_t pid);
    
    /// @brief Get all currently detected games
    [[nodiscard]] std::vector<DetectedGame> GetDetectedGames() const;
    
    /// @brief Is any game running
    [[nodiscard]] bool IsAnyGameRunning() const noexcept;

    // ========================================================================
    // FULLSCREEN DETECTION
    // ========================================================================
    
    /// @brief Check if foreground is fullscreen
    [[nodiscard]] bool IsForegroundFullscreen();
    
    /// @brief Get fullscreen info
    [[nodiscard]] FullscreenInfo GetFullscreenInfo();
    
    /// @brief Check if window is fullscreen
    [[nodiscard]] bool IsWindowFullscreen(HWND hwnd);
    
    /// @brief Get window state
    [[nodiscard]] WindowState GetWindowState(HWND hwnd);

    // ========================================================================
    // LAUNCHER DETECTION
    // ========================================================================
    
    /// @brief Get running launchers
    [[nodiscard]] std::vector<LauncherInfo> GetRunningLaunchers() const;
    
    /// @brief Is launcher running
    [[nodiscard]] bool IsLauncherRunning(LauncherType type) const;
    
    /// @brief Get launcher info
    [[nodiscard]] std::optional<LauncherInfo> GetLauncherInfo(LauncherType type) const;

    // ========================================================================
    // VR DETECTION
    // ========================================================================
    
    /// @brief Is VR active
    [[nodiscard]] bool IsVRActive() const noexcept;
    
    /// @brief Get active VR platform
    [[nodiscard]] VRPlatform GetActiveVRPlatform() const noexcept;

    // ========================================================================
    // DATABASE MANAGEMENT
    // ========================================================================
    
    /// @brief Load game database
    [[nodiscard]] bool LoadDatabase(const std::wstring& path = L"");
    
    /// @brief Get database size
    [[nodiscard]] size_t GetDatabaseSize() const noexcept;
    
    /// @brief Search database
    [[nodiscard]] std::vector<GameEntry> SearchDatabase(const std::string& query, size_t limit = 50);
    
    /// @brief Add user-defined game
    [[nodiscard]] bool AddUserGame(const std::wstring& processName, const std::string& title = "");
    
    /// @brief Remove user-defined game
    [[nodiscard]] bool RemoveUserGame(const std::wstring& processName);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterGameDetectedCallback(GameDetectedCallback callback);
    void RegisterGameExitedCallback(GameExitedCallback callback);
    void RegisterFullscreenChangeCallback(FullscreenChangeCallback callback);
    void RegisterLauncherCallback(LauncherCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] DetectorStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    GameProcessDetector();
    ~GameProcessDetector();
    
    std::unique_ptr<GameProcessDetectorImpl> m_impl;
    std::unordered_set<std::wstring> m_gameExecutables;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetCategoryName(GameCategory category) noexcept;
[[nodiscard]] std::string_view GetLauncherTypeName(LauncherType type) noexcept;
[[nodiscard]] std::string_view GetWindowStateName(WindowState state) noexcept;
[[nodiscard]] std::string_view GetDetectionMethodName(DetectionMethod method) noexcept;
[[nodiscard]] std::string_view GetVRPlatformName(VRPlatform platform) noexcept;

/// @brief Get launcher install path from registry
[[nodiscard]] std::wstring GetLauncherInstallPath(LauncherType type);

/// @brief Detect launcher from process
[[nodiscard]] LauncherType DetectLauncherFromProcess(uint32_t pid);

}  // namespace GameMode
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IS_GAME_PROCESS(pid) \
    ::ShadowStrike::GameMode::GameProcessDetector::Instance().IsGameProcess(pid)

#define SS_IS_FULLSCREEN() \
    ::ShadowStrike::GameMode::GameProcessDetector::Instance().IsForegroundFullscreen()
