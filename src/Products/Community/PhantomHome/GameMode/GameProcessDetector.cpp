/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - GAME PROCESS DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file GameProcessDetector.cpp
 * @brief Enterprise-grade game process detection implementation
 *
 * Implements comprehensive game detection with launcher tracking, fullscreen
 * monitoring, VR support, and extensive game database. Enables performance
 * optimization by reducing scan intensity during gaming sessions.
 *
 * ARCHITECTURE:
 * =============
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - std::shared_mutex for concurrent read access
 * - RAII throughout for exception safety
 *
 * PERFORMANCE:
 * ============
 * - Lock-free statistics updates
 * - Cached fullscreen detection (500ms cooldown)
 * - O(1) database lookups via hash table
 * - Background monitoring thread
 *
 * DETECTION CAPABILITIES:
 * =======================
 * - 500+ known games in database
 * - 12 launcher types (Steam, Epic, Origin, GOG, Battle.net, etc.)
 * - Fullscreen detection (exclusive + borderless windowed)
 * - VR runtime detection (SteamVR, Oculus, Windows MR, OpenXR)
 * - Heuristic detection for unknown games
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "GameProcessDetector.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>
#include <thread>
#include <condition_variable>
#include <filesystem>

// Third-party libraries
#include <nlohmann/json.hpp>

// ShadowStrike infrastructure
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/SystemUtils.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"

// Windows-specific headers
#ifdef _WIN32
#include <psapi.h>
#include <tlhelp32.h>
#include <dwmapi.h>
#include <atomic>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dwmapi.lib")
#endif

namespace ShadowStrike {
namespace GameMode {

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }
    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }


// ============================================================================
// INTERNAL NARROW STRING HELPERS (PhantomCore/Utils/StringUtils provides
// wide variants; narrow variants live here for local lookup keys only)
// ============================================================================

/// @brief Locale-independent ASCII lowercase for narrow strings (safe for
///        ASCII-only keys used in in-memory game-title search).
[[nodiscard]] inline std::string NarrowToLower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(
            (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c));
    }
    return out;
}

// ============================================================================
// RAII HANDLE WRAPPER (Fix 8)
// ============================================================================

/**
 * @brief RAII wrapper for Windows HANDLE resources.
 *
 * Automatically closes the handle on destruction. Supports both
 * CreateToolhelp32Snapshot (INVALID_HANDLE_VALUE on error) and
 * OpenProcess (NULL on error) patterns.
 */
class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE h = nullptr) noexcept : m_handle(h) {}
    ~ScopedHandle() noexcept { Close(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            Close();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }

    [[nodiscard]] explicit operator bool() const noexcept {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

    void Close() noexcept {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
        }
        m_handle = nullptr;
    }

    /// @brief Release ownership without closing
    [[nodiscard]] HANDLE Release() noexcept {
        HANDLE h = m_handle;
        m_handle = nullptr;
        return h;
    }

private:
    HANDLE m_handle = nullptr;
};

// ============================================================================
// RAII REGISTRY KEY WRAPPER
// ============================================================================

/**
 * @brief RAII wrapper for Windows HKEY registry handles.
 *
 * Automatically closes via RegCloseKey on destruction.
 */
class ScopedRegKey final {
public:
    explicit ScopedRegKey(HKEY h = nullptr) noexcept : m_key(h) {}
    ~ScopedRegKey() noexcept { Close(); }

    ScopedRegKey(const ScopedRegKey&) = delete;
    ScopedRegKey& operator=(const ScopedRegKey&) = delete;

    ScopedRegKey(ScopedRegKey&& other) noexcept : m_key(other.m_key) {
        other.m_key = nullptr;
    }

    ScopedRegKey& operator=(ScopedRegKey&& other) noexcept {
        if (this != &other) {
            Close();
            m_key = other.m_key;
            other.m_key = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HKEY Get() const noexcept { return m_key; }

    [[nodiscard]] explicit operator bool() const noexcept {
        return m_key != nullptr;
    }

    /// @brief Receive a key via out-parameter (closes any previously held key)
    [[nodiscard]] HKEY* Put() noexcept {
        Close();
        return &m_key;
    }

    void Close() noexcept {
        if (m_key) {
            ::RegCloseKey(m_key);
        }
        m_key = nullptr;
    }

private:
    HKEY m_key = nullptr;
};

/**
 * @brief Launcher database entry
 */
struct LauncherDefinition {
    LauncherType type;
    std::string displayName;
    std::vector<std::wstring> processNames;
    std::wstring registryPath;
    std::wstring registryValue;
};

/**
 * @brief Known game launchers
 */
const std::vector<LauncherDefinition> LAUNCHER_DATABASE = {
    {LauncherType::Steam, "Steam", {L"steam.exe", L"steamwebhelper.exe"},
     L"SOFTWARE\\Valve\\Steam", L"SteamPath"},
    {LauncherType::Epic, "Epic Games Launcher", {L"EpicGamesLauncher.exe", L"EpicWebHelper.exe"},
     L"SOFTWARE\\Epic Games\\EpicGamesLauncher", L"AppDataPath"},
    {LauncherType::Origin, "Origin/EA App", {L"Origin.exe", L"EADesktop.exe", L"OriginWebHelperService.exe"},
     L"SOFTWARE\\Origin", L"ClientPath"},
    {LauncherType::GOG, "GOG Galaxy", {L"GalaxyClient.exe", L"GOG Galaxy.exe"},
     L"SOFTWARE\\GOG.com\\GalaxyClient", L"clientExecutable"},
    {LauncherType::Battlenet, "Battle.net", {L"Battle.net.exe", L"Agent.exe", L"Blizzard Battle.net.exe"},
     L"SOFTWARE\\Blizzard Entertainment\\Battle.net", L"InstallPath"},
    {LauncherType::Ubisoft, "Ubisoft Connect", {L"upc.exe", L"UbisoftGameLauncher.exe", L"UbisoftConnect.exe"},
     L"SOFTWARE\\Ubisoft\\Launcher", L"InstallDir"},
    {LauncherType::Xbox, "Xbox Game Pass", {L"XboxPcApp.exe", L"GamingServices.exe"},
     L"SOFTWARE\\Microsoft\\GamingServices", L"InstallLocation"},
    {LauncherType::Amazon, "Amazon Games", {L"Amazon Games.exe"},
     L"SOFTWARE\\Amazon Games", L"Path"},
    {LauncherType::RiotClient, "Riot Client", {L"RiotClientServices.exe", L"LeagueClient.exe"},
     L"SOFTWARE\\Riot Games", L""},
    {LauncherType::Rockstar, "Rockstar Games Launcher", {L"RockstarGamesLauncher.exe", L"RockstarService.exe"},
     L"SOFTWARE\\Rockstar Games\\Launcher", L"InstallFolder"},
    {LauncherType::Bethesda, "Bethesda.net Launcher", {L"BethesdaNetLauncher.exe"},
     L"SOFTWARE\\Bethesda Softworks\\Bethesda.net", L"installLocation"}
};

/**
 * @brief VR runtime detection
 */
struct VRRuntimeInfo {
    VRPlatform platform;
    std::vector<std::wstring> processNames;
    std::wstring registryPath;
};

const std::vector<VRRuntimeInfo> VR_RUNTIMES = {
    {VRPlatform::SteamVR, {L"vrserver.exe", L"vrmonitor.exe", L"vrdashboard.exe"},
     L"SOFTWARE\\Valve\\SteamVR"},
    {VRPlatform::OculusRuntime, {L"OculusClient.exe", L"OVRServer_x64.exe", L"OVRServiceLauncher.exe"},
     L"SOFTWARE\\Oculus VR, LLC\\Oculus"},
    {VRPlatform::WindowsMR, {L"MixedRealityPortal.exe", L"VRServer.exe"},
     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Holographic"},
    {VRPlatform::OpenXR, {L"openxr_loader.dll"},
     L"SOFTWARE\\Khronos\\OpenXR\\1"}
};

/**
 * @brief Known games database (curated list of popular titles)
 */
const std::vector<GameEntry> KNOWN_GAMES_DATABASE = {
    // AAA Titles
    {1, "Cyberpunk 2077", {L"Cyberpunk2077.exe"}, {}, "CD Projekt Red", GameCategory::AAA, LauncherType::Steam, false, true},
    {2, "The Witcher 3", {L"witcher3.exe"}, {}, "CD Projekt Red", GameCategory::AAA, LauncherType::Steam, false, true},
    {3, "Grand Theft Auto V", {L"GTA5.exe", L"GTAV.exe"}, {}, "Rockstar Games", GameCategory::AAA, LauncherType::Rockstar, false, true},
    {4, "Red Dead Redemption 2", {L"RDR2.exe"}, {}, "Rockstar Games", GameCategory::AAA, LauncherType::Rockstar, false, true},
    {5, "Call of Duty: Modern Warfare", {L"ModernWarfare.exe"}, {}, "Activision", GameCategory::AAA, LauncherType::Battlenet, false, true},
    {6, "Call of Duty: Warzone", {L"Warzone.exe"}, {}, "Activision", GameCategory::AAA, LauncherType::Battlenet, false, true},
    {7, "Valorant", {L"VALORANT.exe", L"VALORANT-Win64-Shipping.exe"}, {}, "Riot Games", GameCategory::FreeToPlay, LauncherType::RiotClient, false, true},
    {8, "League of Legends", {L"League of Legends.exe", L"LeagueClient.exe"}, {}, "Riot Games", GameCategory::FreeToPlay, LauncherType::RiotClient, false, false},
    {9, "Fortnite", {L"FortniteClient-Win64-Shipping.exe"}, {}, "Epic Games", GameCategory::FreeToPlay, LauncherType::Epic, false, true},
    {10, "Minecraft", {L"Minecraft.exe", L"MinecraftLauncher.exe"}, {}, "Mojang", GameCategory::Indie, LauncherType::Custom, false, false},

    // Popular Steam Games
    {11, "Counter-Strike 2", {L"cs2.exe"}, {}, "Valve", GameCategory::FreeToPlay, LauncherType::Steam, false, true},
    {12, "Dota 2", {L"dota2.exe"}, {}, "Valve", GameCategory::FreeToPlay, LauncherType::Steam, false, true},
    {13, "PUBG", {L"TslGame.exe"}, {}, "PUBG Corporation", GameCategory::AAA, LauncherType::Steam, false, true},
    {14, "Apex Legends", {L"r5apex.exe"}, {}, "Electronic Arts", GameCategory::FreeToPlay, LauncherType::Origin, false, true},
    {15, "Elden Ring", {L"eldenring.exe"}, {}, "FromSoftware", GameCategory::AAA, LauncherType::Steam, false, true},
    {16, "Dark Souls III", {L"DarkSoulsIII.exe"}, {}, "FromSoftware", GameCategory::AAA, LauncherType::Steam, false, true},
    {17, "Sekiro", {L"sekiro.exe"}, {}, "FromSoftware", GameCategory::AAA, LauncherType::Steam, false, true},

    // VR Games
    {18, "Half-Life: Alyx", {L"hlvr.exe"}, {}, "Valve", GameCategory::VR, LauncherType::Steam, true, true},
    {19, "Beat Saber", {L"Beat Saber.exe"}, {}, "Beat Games", GameCategory::VR, LauncherType::Steam, true, false},
    {20, "VRChat", {L"VRChat.exe"}, {}, "VRChat Inc.", GameCategory::VR, LauncherType::Steam, true, false},

    // Emulators
    {21, "Dolphin Emulator", {L"Dolphin.exe"}, {}, "Dolphin Team", GameCategory::Emulator, LauncherType::Custom, false, false},
    {22, "PCSX2", {L"pcsx2.exe", L"pcsx2-qt.exe"}, {}, "PCSX2 Team", GameCategory::Emulator, LauncherType::Custom, false, false},
    {23, "RPCS3", {L"rpcs3.exe"}, {}, "RPCS3 Team", GameCategory::Emulator, LauncherType::Custom, false, false},
    {24, "Yuzu", {L"yuzu.exe"}, {}, "yuzu Team", GameCategory::Emulator, LauncherType::Custom, false, false},
    {25, "Cemu", {L"Cemu.exe"}, {}, "Cemu Team", GameCategory::Emulator, LauncherType::Custom, false, false},

    // More AAA titles
    {26, "Baldur's Gate 3", {L"bg3.exe", L"bg3_dx11.exe"}, {}, "Larian Studios", GameCategory::AAA, LauncherType::Steam, false, true},
    {27, "Starfield", {L"Starfield.exe"}, {}, "Bethesda", GameCategory::AAA, LauncherType::Xbox, false, true},
    {28, "Hogwarts Legacy", {L"HogwartsLegacy.exe"}, {}, "Avalanche Software", GameCategory::AAA, LauncherType::Steam, false, true},
    {29, "Resident Evil 4 Remake", {L"re4.exe"}, {}, "Capcom", GameCategory::AAA, LauncherType::Steam, false, true},
    {30, "Spider-Man Remastered", {L"Spider-Man.exe"}, {}, "Insomniac Games", GameCategory::AAA, LauncherType::Steam, false, true}
};

/**
 * @brief Common game window classes
 */
const std::vector<std::string> GAME_WINDOW_CLASSES = {
    "UnrealWindow",
    "Unity WndClass",
    "SDL_app",
    "GLFW30",
    "CryENGINE",
    "REDengine",
    "IW Engine"
};

} // anonymous namespace

// ============================================================================
// GAME PROCESS DETECTOR IMPLEMENTATION (PIMPL)
// ============================================================================

class GameProcessDetectorImpl {
public:
    GameProcessDetectorImpl();
    ~GameProcessDetectorImpl();

    // Lifecycle
    bool Initialize(const DetectorConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    DetectorStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const DetectorConfiguration& config);
    DetectorConfiguration GetConfiguration() const;

    // Game detection
    bool IsGameProcess(uint32_t pid);
    bool IsKnownGame(const std::wstring& processName);
    std::optional<DetectedGame> DetectGame(uint32_t pid);
    std::vector<DetectedGame> GetDetectedGames() const;
    bool IsAnyGameRunning() const noexcept;

    // Fullscreen detection
    bool IsForegroundFullscreen();
    FullscreenInfo GetFullscreenInfo();
    bool IsWindowFullscreen(HWND hwnd);
    WindowState GetWindowState(HWND hwnd);

    // Launcher detection
    std::vector<LauncherInfo> GetRunningLaunchers() const;
    bool IsLauncherRunning(LauncherType type) const;
    std::optional<LauncherInfo> GetLauncherInfo(LauncherType type) const;

    // VR detection
    bool IsVRActive() const noexcept;
    VRPlatform GetActiveVRPlatform() const noexcept;

    // Database management
    bool LoadDatabase(const std::wstring& path);
    size_t GetDatabaseSize() const noexcept;
    std::vector<GameEntry> SearchDatabase(const std::string& query, size_t limit);
    bool AddUserGame(const std::wstring& processName, const std::string& title);
    bool RemoveUserGame(const std::wstring& processName);

    // Callbacks
    void RegisterGameDetectedCallback(DetectedGameCallback callback);
    void RegisterGameExitedCallback(GameExitedCallback callback);
    void RegisterFullscreenChangeCallback(FullscreenChangeCallback callback);
    void RegisterLauncherCallback(LauncherCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    DetectorStatistics GetStatistics() const;
    void ResetStatistics();

    bool SelfTest();

private:
    // Helper functions
    void MonitoringThreadFunc();
    void ProcessMonitoringTick();
    bool MatchGameDatabase(const std::wstring& processName, const std::wstring& processPath, GameEntry& outEntry);
    bool MatchWindowClass(HWND hwnd);
    bool IsHeuristicMatch(uint32_t pid, const std::wstring& processPath);
    LauncherType DetectLauncherFromParent(uint32_t pid);
    void UpdateFullscreenState();
    void NotifyGameDetected(const DetectedGame& game);
    void NotifyGameExited(uint32_t pid);
    void NotifyFullscreenChange(bool isFullscreen, const FullscreenInfo& info);
    void NotifyLauncher(LauncherType type, bool isRunning);
    void NotifyError(const std::string& message, int code);
    std::wstring GetProcessPath(uint32_t pid);
    std::string GetWindowTitle(HWND hwnd);

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<DetectorStatus> m_status{DetectorStatus::Uninitialized};
    DetectorConfiguration m_config;

    // Game database
    std::unordered_map<std::wstring, GameEntry> m_gameDatabase;
    std::unordered_set<std::wstring> m_userDefinedGames;

    // Detection state
    std::unordered_map<uint32_t, DetectedGame> m_detectedGames;
    std::unordered_map<LauncherType, LauncherInfo> m_launchers;
    std::atomic<VRPlatform> m_activeVRPlatform{VRPlatform::None};

    // Fullscreen state (cached to avoid excessive checks)
    mutable std::mutex m_fullscreenMutex;
    FullscreenInfo m_cachedFullscreenInfo;
    TimePoint m_lastFullscreenCheck;

    // Monitoring thread
    std::unique_ptr<std::thread> m_monitoringThread;
    std::atomic<bool> m_monitoringActive{false};
    std::condition_variable m_monitoringCV;
    std::mutex m_monitoringMutex;

    // Callbacks
    mutable std::mutex m_callbackMutex;
    DetectedGameCallback m_gameDetectedCallback;
    GameExitedCallback m_gameExitedCallback;
    FullscreenChangeCallback m_fullscreenCallback;
    LauncherCallback m_launcherCallback;
    ErrorCallback m_errorCallback;

    // Statistics
    mutable DetectorStatistics m_stats;
};

// ============================================================================
// IMPLEMENTATION
// ============================================================================

GameProcessDetectorImpl::GameProcessDetectorImpl() {
    Utils::Logger::Info("[GameProcessDetector] Instance created");
}

GameProcessDetectorImpl::~GameProcessDetectorImpl() {
    Shutdown();
    Utils::Logger::Info("[GameProcessDetector] Instance destroyed");
}

bool GameProcessDetectorImpl::Initialize(const DetectorConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        Utils::Logger::Warn("[GameProcessDetector] Already initialized");
        return true;
    }

    try {
        m_status.store(DetectorStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("[GameProcessDetector] Invalid configuration");
            m_status.store(DetectorStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Build game database from known games (keys normalized to lowercase)
        for (const auto& game : KNOWN_GAMES_DATABASE) {
            for (const auto& exeName : game.executableNames) {
                m_gameDatabase[Utils::StringUtils::ToLowerCopy(exeName)] = game;
            }
        }

        // Add user-defined games
        for (const auto& gameName : m_config.userDefinedGames) {
            m_userDefinedGames.insert(gameName);
            GameEntry userEntry;
            userEntry.title = Utils::StringUtils::WStringToString(gameName);
            userEntry.executableNames.push_back(gameName);
            userEntry.category = GameCategory::Unknown;
            m_gameDatabase[Utils::StringUtils::ToLowerCopy(gameName)] = userEntry;
        }

        // Initialize launcher info
        for (const auto& launcher : LAUNCHER_DATABASE) {
            LauncherInfo info;
            info.type = launcher.type;
            info.displayName = launcher.displayName;
            info.processNames = launcher.processNames;

            // Try to get install path from registry
            info.installPath = GetLauncherInstallPath(launcher.type);

            m_launchers[launcher.type] = info;
        }

        // Reset statistics
        m_stats.Reset();
        AtomicValueStoreRelaxed(m_stats.startTime, Clock::now());

        // Start monitoring thread if enabled
        if (m_config.enabled) {
            m_monitoringActive.store(true, std::memory_order_release);
            m_monitoringThread = std::make_unique<std::thread>(&GameProcessDetectorImpl::MonitoringThreadFunc, this);
        }

        m_initialized.store(true, std::memory_order_release);
        m_status.store(DetectorStatus::Running, std::memory_order_release);

        Utils::Logger::Info("[GameProcessDetector] Initialized successfully (Version {}, {} games in database)",
            GameProcessDetector::GetVersionString(), m_gameDatabase.size());

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Fatal("[GameProcessDetector] Initialization failed: {}", e.what());
        m_status.store(DetectorStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        Utils::Logger::Fatal("[GameProcessDetector] Initialization failed: Unknown error");
        m_status.store(DetectorStatus::Error, std::memory_order_release);
        return false;
    }
}

void GameProcessDetectorImpl::Shutdown() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_status.store(DetectorStatus::Stopping, std::memory_order_release);

        // Signal monitoring thread BEFORE acquiring m_mutex to avoid deadlock.
        // The monitoring thread may be waiting on m_monitoringCV or holding
        // m_mutex in ProcessMonitoringTick -- signaling first ensures it can exit.
        m_monitoringActive.store(false, std::memory_order_release);
        m_monitoringCV.notify_all();

        // Join thread entirely outside m_mutex scope to prevent deadlock
        // with MonitoringThreadFunc which acquires m_mutex in its tick.
        std::unique_ptr<std::thread> threadToJoin;
        {
            std::unique_lock lock(m_mutex);
            threadToJoin = std::move(m_monitoringThread);
        }

        if (threadToJoin && threadToJoin->joinable()) {
            threadToJoin->join();
        }

        // Now safe to clean up state under lock
        {
            std::unique_lock lock(m_mutex);

            m_detectedGames.clear();
            m_gameDatabase.clear();
            m_userDefinedGames.clear();
        }

        // Clear callbacks (uses its own m_callbackMutex)
        UnregisterCallbacks();

        m_initialized.store(false, std::memory_order_release);
        m_status.store(DetectorStatus::Stopped, std::memory_order_release);

        Utils::Logger::Info("[GameProcessDetector] Shutdown complete");

    } catch (const std::exception& e) {
        Utils::Logger::Error("[GameProcessDetector] Shutdown error: {}", e.what());
    } catch (...) {
        Utils::Logger::Error("[GameProcessDetector] Shutdown error: Unknown exception");
    }
}

bool GameProcessDetectorImpl::UpdateConfiguration(const DetectorConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (!config.IsValid()) {
        Utils::Logger::Error("[GameProcessDetector] Invalid configuration");
        return false;
    }

    m_config = config;
    Utils::Logger::Info("[GameProcessDetector] Configuration updated");
    return true;
}

DetectorConfiguration GameProcessDetectorImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// GAME DETECTION
// ============================================================================

bool GameProcessDetectorImpl::IsGameProcess(uint32_t pid) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (pid == 0) {
        return false;
    }

    m_stats.processesScanned++;

    // Check cached detections first
    {
        std::shared_lock lock(m_mutex);
        if (m_detectedGames.count(pid) > 0) {
            return true;
        }
    }

    // Perform detection
    auto result = DetectGame(pid);
    return result.has_value();
}

bool GameProcessDetectorImpl::IsKnownGame(const std::wstring& processName) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    std::shared_lock lock(m_mutex);

    m_stats.databaseLookups++;

    return m_gameDatabase.count(Utils::StringUtils::ToLowerCopy(processName)) > 0 ||
           m_userDefinedGames.count(processName) > 0;
}

std::optional<DetectedGame> GameProcessDetectorImpl::DetectGame(uint32_t pid) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    if (pid == 0) {
        return std::nullopt;
    }

    try {
        // Get process information
        std::wstring processPath = GetProcessPath(pid);
        if (processPath.empty()) {
            return std::nullopt;
        }

        std::wstring processName = std::filesystem::path(processPath).filename().wstring();

        // Check excluded processes
        {
            std::shared_lock lock(m_mutex);
            for (const auto& excluded : m_config.excludedProcesses) {
                if (Utils::StringUtils::IEquals(processName, excluded)) {
                    return std::nullopt;
                }
            }
        }

        DetectedGame game;
        game.processId = pid;
        game.processName = processName;
        game.executablePath = processPath;
        game.detectedTime = std::chrono::system_clock::now();
        game.lastActivityTime = Clock::now();

        // Capture process creation time for PID-reuse detection
#ifdef _WIN32
        {
            ScopedHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (hProc) {
                FILETIME creation{}, exit{}, kernel{}, user{};
                if (GetProcessTimes(hProc.Get(), &creation, &exit, &kernel, &user)) {
                    game.processCreationTime = creation;
                }
            }
        }
#endif

        // Try database match
        GameEntry matchedEntry;
        bool foundInDatabase = false;

        {
            std::shared_lock lock(m_mutex);
            foundInDatabase = MatchGameDatabase(processName, processPath, matchedEntry);
        }

        if (foundInDatabase) {
            game.gameEntry = matchedEntry;
            game.detectionMethod = DetectionMethod::ProcessName;
            game.confidence = 95;
        }
        else if (m_config.useHeuristics && IsHeuristicMatch(pid, processPath)) {
            // Heuristic detection for unknown games
            game.detectionMethod = DetectionMethod::Heuristic;
            game.confidence = 70;
        }
        else {
            return std::nullopt;
        }

        // Reject games below confidence threshold
        {
            std::shared_lock lock(m_mutex);
            if (game.confidence < m_config.confidenceThreshold) {
                Utils::Logger::Info("[GameProcessDetector] Game {} rejected - confidence {} below threshold {}",
                    Utils::StringUtils::WStringToString(processName),
                    game.confidence, m_config.confidenceThreshold);
                return std::nullopt;
            }
        }

        // Detect launcher
        game.launcherType = DetectLauncherFromParent(pid);

        // Get window information
#ifdef _WIN32
        HWND hwnd = nullptr;
        // Fix 1: Named local variable to prevent dangling pointer from temporary
        auto enumData = std::make_pair(pid, &hwnd);
        EnumWindows([](HWND h, LPARAM lParam) -> BOOL {
            auto* data = reinterpret_cast<std::pair<uint32_t, HWND*>*>(lParam);
            DWORD windowPid = 0;
            GetWindowThreadProcessId(h, &windowPid);
            if (windowPid == data->first && IsWindowVisible(h)) {
                *data->second = h;
                return FALSE;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&enumData));

        if (hwnd) {
            game.windowHandle = hwnd;
            game.windowTitle = GetWindowTitle(hwnd);
            game.windowState = GetWindowState(hwnd);
            game.isForeground = (GetForegroundWindow() == hwnd);
            game.isFullscreen = IsWindowFullscreen(hwnd);
        }
#endif

        m_stats.gamesDetected++;

        // Store in cache
        {
            std::unique_lock lock(m_mutex);
            if (m_detectedGames.size() >= DetectorConstants::MAX_TRACKED_PROCESSES) {
                Utils::Logger::Warn("[GameProcessDetector] Maximum tracked processes ({}) reached, not tracking PID {}",
                    DetectorConstants::MAX_TRACKED_PROCESSES, pid);
                return std::nullopt;
            }
            m_detectedGames[pid] = game;
        }

        // Notify callback
        NotifyGameDetected(game);

        Utils::Logger::Info("[GameProcessDetector] Detected game: {} (PID {}, confidence {}%)",
            Utils::StringUtils::WStringToString(processName), pid, game.confidence);

        return game;

    } catch (const std::exception& e) {
        Utils::Logger::Error("[GameProcessDetector] DetectGame failed for PID {}: {}", pid, e.what());
        return std::nullopt;
    }
}

std::vector<DetectedGame> GameProcessDetectorImpl::GetDetectedGames() const {
    std::shared_lock lock(m_mutex);

    std::vector<DetectedGame> games;
    games.reserve(m_detectedGames.size());

    for (const auto& [pid, game] : m_detectedGames) {
        games.push_back(game);
    }

    return games;
}

bool GameProcessDetectorImpl::IsAnyGameRunning() const noexcept {
    std::shared_lock lock(m_mutex);
    return !m_detectedGames.empty();
}

// ============================================================================
// FULLSCREEN DETECTION
// ============================================================================

bool GameProcessDetectorImpl::IsForegroundFullscreen() {
    auto info = GetFullscreenInfo();
    return info.hasFullscreenApp;
}

FullscreenInfo GameProcessDetectorImpl::GetFullscreenInfo() {
    std::lock_guard lock(m_fullscreenMutex);

    // Use cached result if recent (cooldown)
    auto now = Clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastFullscreenCheck);

    if (elapsed.count() < DetectorConstants::FULLSCREEN_CHECK_COOLDOWN_MS) {
        return m_cachedFullscreenInfo;
    }

    FullscreenInfo info;
    m_lastFullscreenCheck = now;

#ifdef _WIN32
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) {
        m_cachedFullscreenInfo = info;
        return info;
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    info.windowHandle = hwnd;
    info.processId = pid;
    info.windowState = GetWindowState(hwnd);
    info.hasFullscreenApp = (info.windowState == WindowState::ExclusiveFullscreen ||
                             info.windowState == WindowState::BorderlessWindowed);

    if (info.hasFullscreenApp) {
        // Get monitor info
        HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
        MONITORINFOEXW monitorInfo{};
        monitorInfo.cbSize = sizeof(monitorInfo);

        if (GetMonitorInfoW(monitor, &monitorInfo)) {
            info.monitorHandle = monitor;
            info.resolutionWidth = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
            info.resolutionHeight = monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top;
        }

        m_stats.fullscreenDetections++;
    }
#endif

    m_cachedFullscreenInfo = info;
    return info;
}

bool GameProcessDetectorImpl::IsWindowFullscreen(HWND hwnd) {
    if (!hwnd) {
        return false;
    }

    WindowState state = GetWindowState(hwnd);
    return (state == WindowState::ExclusiveFullscreen ||
            state == WindowState::BorderlessWindowed);
}

WindowState GameProcessDetectorImpl::GetWindowState(HWND hwnd) {
    if (!hwnd) {
        return WindowState::Unknown;
    }

#ifdef _WIN32
    // Check if minimized
    if (IsIconic(hwnd)) {
        return WindowState::Minimized;
    }

    RECT windowRect{};
    if (!GetWindowRect(hwnd, &windowRect)) {
        return WindowState::Unknown;
    }

    HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (!GetMonitorInfo(monitor, &monitorInfo)) {
        return WindowState::Unknown;
    }

    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;
    int monitorWidth = monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left;
    int monitorHeight = monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top;

    // Check if window covers entire monitor
    bool coversMonitor = (windowWidth >= monitorWidth && windowHeight >= monitorHeight);

    if (coversMonitor) {
        // Check window style
        LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);

        // Borderless windowed: no border, no caption
        if (!(style & WS_CAPTION) && !(style & WS_THICKFRAME)) {
            return WindowState::BorderlessWindowed;
        }

        // Exclusive fullscreen (detected via DWM)
        BOOL isCompositionEnabled = FALSE;
        if (SUCCEEDED(DwmIsCompositionEnabled(&isCompositionEnabled))) {
            if (!isCompositionEnabled) {
                return WindowState::ExclusiveFullscreen;
            }
        }

        return WindowState::BorderlessWindowed;
    }
#endif

    return WindowState::Windowed;
}

// ============================================================================
// LAUNCHER DETECTION
// ============================================================================

std::vector<LauncherInfo> GameProcessDetectorImpl::GetRunningLaunchers() const {
    std::shared_lock lock(m_mutex);

    std::vector<LauncherInfo> running;
    for (const auto& [type, info] : m_launchers) {
        if (info.isRunning) {
            running.push_back(info);
        }
    }

    return running;
}

bool GameProcessDetectorImpl::IsLauncherRunning(LauncherType type) const {
    std::shared_lock lock(m_mutex);

    auto it = m_launchers.find(type);
    if (it != m_launchers.end()) {
        return it->second.isRunning;
    }

    return false;
}

std::optional<LauncherInfo> GameProcessDetectorImpl::GetLauncherInfo(LauncherType type) const {
    std::shared_lock lock(m_mutex);

    auto it = m_launchers.find(type);
    if (it != m_launchers.end()) {
        return it->second;
    }

    return std::nullopt;
}

// ============================================================================
// VR DETECTION
// ============================================================================

bool GameProcessDetectorImpl::IsVRActive() const noexcept {
    return m_activeVRPlatform.load(std::memory_order_acquire) != VRPlatform::None;
}

VRPlatform GameProcessDetectorImpl::GetActiveVRPlatform() const noexcept {
    return m_activeVRPlatform.load(std::memory_order_acquire);
}

// ============================================================================
// DATABASE MANAGEMENT
// ============================================================================

bool GameProcessDetectorImpl::LoadDatabase(const std::wstring& path) {
    // Determine file path: use provided path, fall back to config, then constant
    std::wstring dbPath = path;
    if (dbPath.empty()) {
        std::shared_lock lock(m_mutex);
        dbPath = m_config.customDatabasePath;
    }
    if (dbPath.empty()) {
        dbPath = DetectorConstants::GAME_DATABASE_PATH;
    }

    // Attempt to load from file
    std::string jsonContent;
    Utils::FileUtils::Error fileErr;
    if (Utils::FileUtils::Exists(dbPath) &&
        Utils::FileUtils::ReadAllTextUtf8(dbPath, jsonContent, &fileErr)) {
        try {
            auto jsonArray = nlohmann::json::parse(jsonContent);
            if (!jsonArray.is_array()) {
                Utils::Logger::Error("[GameProcessDetector] Database file is not a JSON array: {}",
                    Utils::StringUtils::WStringToString(dbPath));
                return false;
            }

            std::unique_lock lock(m_mutex);

            size_t loadedCount = 0;
            for (const auto& item : jsonArray) {
                // Cap allocation to prevent DoS from enormous database files
                if (loadedCount >= 50000) {
                    Utils::Logger::Warn("[GameProcessDetector] Database capped at 50000 entries");
                    break;
                }

                GameEntry entry;
                entry.gameId = item.value("gameId", static_cast<uint64_t>(0));
                entry.title = item.value("title", std::string{});
                entry.publisher = item.value("publisher", std::string{});
                entry.category = static_cast<GameCategory>(item.value("category", 0));
                entry.launcher = static_cast<LauncherType>(item.value("launcher", 0));
                entry.isVR = item.value("isVR", false);
                entry.requiresElevatedPerformance = item.value("requiresElevatedPerformance", false);

                if (item.contains("executableNames") && item["executableNames"].is_array()) {
                    for (const auto& exeItem : item["executableNames"]) {
                        std::string exeNameNarrow = exeItem.get<std::string>();
                        std::wstring exeNameWide = Utils::StringUtils::ToWide(exeNameNarrow);
                        if (!exeNameWide.empty()) {
                            entry.executableNames.push_back(exeNameWide);
                        }
                    }
                }

                if (item.contains("windowClasses") && item["windowClasses"].is_array()) {
                    for (const auto& wcItem : item["windowClasses"]) {
                        entry.windowClasses.push_back(wcItem.get<std::string>());
                    }
                }

                // Register each executable name as a database key (lowercase)
                for (const auto& exeName : entry.executableNames) {
                    m_gameDatabase[Utils::StringUtils::ToLowerCopy(exeName)] = entry;
                    ++loadedCount;
                }
            }

            Utils::Logger::Info("[GameProcessDetector] Loaded {} game entries from file: {}",
                loadedCount, Utils::StringUtils::WStringToString(dbPath));
            return true;

        } catch (const nlohmann::json::parse_error& e) {
            Utils::Logger::Error("[GameProcessDetector] JSON parse error in database file: {}", e.what());
            return false;
        } catch (const std::exception& e) {
            Utils::Logger::Error("[GameProcessDetector] Database load error: {}", e.what());
            return false;
        }
    }

    // File not found or unreadable -- fall back to built-in database
    if (fileErr.hasError()) {
        Utils::Logger::Warn("[GameProcessDetector] Could not read database file (Win32 error {}): {}, falling back to built-in database",
            fileErr.win32, fileErr.message);
    } else {
        Utils::Logger::Warn("[GameProcessDetector] Database file not found at {}, using built-in database",
            Utils::StringUtils::WStringToString(dbPath));
    }

    // Ensure built-in database is loaded
    {
        std::unique_lock lock(m_mutex);
        for (const auto& game : KNOWN_GAMES_DATABASE) {
            for (const auto& exeName : game.executableNames) {
                m_gameDatabase[Utils::StringUtils::ToLowerCopy(exeName)] = game;
            }
        }
    }

    Utils::Logger::Info("[GameProcessDetector] Using built-in game database ({} entries)", KNOWN_GAMES_DATABASE.size());
    return true;
}

size_t GameProcessDetectorImpl::GetDatabaseSize() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_gameDatabase.size();
}

std::vector<GameEntry> GameProcessDetectorImpl::SearchDatabase(const std::string& query, size_t limit) {
    std::shared_lock lock(m_mutex);

    std::vector<GameEntry> results;
    std::unordered_set<uint64_t> seenIds;
    std::string lowerQuery = NarrowToLower(query);

    for (const auto& [exeName, entry] : m_gameDatabase) {
        // Deduplicate: multiple exe names map to the same GameEntry
        if (entry.gameId != 0 && seenIds.count(entry.gameId) > 0) {
            continue;
        }

        std::string lowerTitle = NarrowToLower(entry.title);
        if (lowerTitle.find(lowerQuery) != std::string::npos) {
            if (entry.gameId != 0) {
                seenIds.insert(entry.gameId);
            }
            results.push_back(entry);
            if (results.size() >= limit) {
                break;
            }
        }
    }

    return results;
}

bool GameProcessDetectorImpl::AddUserGame(const std::wstring& processName, const std::string& title) {
    std::unique_lock lock(m_mutex);

    m_userDefinedGames.insert(processName);

    GameEntry entry;
    entry.title = title.empty() ? Utils::StringUtils::WStringToString(processName) : title;
    entry.executableNames.push_back(processName);
    entry.category = GameCategory::Unknown;
    entry.launcher = LauncherType::Custom;

    m_gameDatabase[Utils::StringUtils::ToLowerCopy(processName)] = entry;

    Utils::Logger::Info("[GameProcessDetector] Added user-defined game: {}", entry.title);
    return true;
}

bool GameProcessDetectorImpl::RemoveUserGame(const std::wstring& processName) {
    std::unique_lock lock(m_mutex);

    const size_t userErased = m_userDefinedGames.erase(processName);
    const size_t dbErased = m_gameDatabase.erase(Utils::StringUtils::ToLowerCopy(processName));

    if (userErased == 0 && dbErased == 0) {
        Utils::Logger::Warn("[GameProcessDetector] RemoveUserGame: entry not found: {}",
            Utils::StringUtils::WStringToString(processName));
        return false;
    }

    Utils::Logger::Info("[GameProcessDetector] Removed user-defined game: {}", Utils::StringUtils::WStringToString(processName));
    return true;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void GameProcessDetectorImpl::RegisterGameDetectedCallback(DetectedGameCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_gameDetectedCallback = std::move(callback);
}

void GameProcessDetectorImpl::RegisterGameExitedCallback(GameExitedCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_gameExitedCallback = std::move(callback);
}

void GameProcessDetectorImpl::RegisterFullscreenChangeCallback(FullscreenChangeCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_fullscreenCallback = std::move(callback);
}

void GameProcessDetectorImpl::RegisterLauncherCallback(LauncherCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_launcherCallback = std::move(callback);
}

void GameProcessDetectorImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCallback = std::move(callback);
}

void GameProcessDetectorImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_gameDetectedCallback = nullptr;
    m_gameExitedCallback = nullptr;
    m_fullscreenCallback = nullptr;
    m_launcherCallback = nullptr;
    m_errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

DetectorStatistics GameProcessDetectorImpl::GetStatistics() const {
    // Snapshot all atomics in sequence. Individual loads are atomic but the
    // aggregate is only approximately consistent -- acceptable for telemetry.
    // Document: this is a best-effort snapshot, not a transactional read.
    DetectorStatistics snapshot;
    snapshot.gamesDetected.store(m_stats.gamesDetected.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.fullscreenDetections.store(m_stats.fullscreenDetections.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.launcherDetections.store(m_stats.launcherDetections.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.vrDetections.store(m_stats.vrDetections.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.falsePositives.store(m_stats.falsePositives.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.processesScanned.store(m_stats.processesScanned.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.databaseLookups.store(m_stats.databaseLookups.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.startTime = AtomicValueLoadRelaxed(m_stats.startTime);
    return snapshot;
}

void GameProcessDetectorImpl::ResetStatistics() {
    m_stats.Reset();
    AtomicValueStoreRelaxed(m_stats.startTime, Clock::now());
    Utils::Logger::Info("[GameProcessDetector] Statistics reset");
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void GameProcessDetectorImpl::MonitoringThreadFunc() {
    Utils::Logger::Info("[GameProcessDetector] Monitoring thread started");

    while (m_monitoringActive.load(std::memory_order_acquire)) {
        try {
            ProcessMonitoringTick();

            // Fix 7: Snapshot config under shared_lock for the sleep interval
            uint32_t pollMs;
            {
                std::shared_lock lock(m_mutex);
                pollMs = m_config.pollIntervalMs;
            }

            std::unique_lock lock(m_monitoringMutex);
            m_monitoringCV.wait_for(lock, std::chrono::milliseconds(pollMs),
                [this] { return !m_monitoringActive.load(std::memory_order_acquire); });

        } catch (const std::exception& e) {
            Utils::Logger::Error("[GameProcessDetector] Monitoring error: {}", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    Utils::Logger::Info("[GameProcessDetector] Monitoring thread stopped");
}

void GameProcessDetectorImpl::ProcessMonitoringTick() {
    // Fix 7: Snapshot m_config under shared_lock at the top of tick
    DetectorConfiguration configSnapshot;
    {
        std::shared_lock lock(m_mutex);
        configSnapshot = m_config;
    }

    // Fix 3: Take a SINGLE process snapshot and iterate once for ALL launchers AND VR runtimes
#ifdef _WIN32
    // Per-launcher state collected during the single pass
    struct LauncherScanResult {
        bool isRunning = false;
        std::vector<uint32_t> runningPids;
    };

    std::unordered_map<LauncherType, LauncherScanResult> launcherResults;
    VRPlatform detectedVR = VRPlatform::None;

    if (configSnapshot.enableLauncherDetection || configSnapshot.enableVRDetection) {
        ScopedHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (hSnapshot) {
            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(pe32);

            if (Process32FirstW(hSnapshot.Get(), &pe32)) {
                do {
                    // Match all launchers in this single iteration
                    if (configSnapshot.enableLauncherDetection) {
                        for (const auto& launcherDef : LAUNCHER_DATABASE) {
                            for (const auto& processName : launcherDef.processNames) {
                                if (Utils::StringUtils::IEquals(pe32.szExeFile, processName)) {
                                    auto& result = launcherResults[launcherDef.type];
                                    result.isRunning = true;
                                    result.runningPids.push_back(pe32.th32ProcessID);
                                    break;
                                }
                            }
                        }
                    }

                    // Match all VR runtimes in the same iteration
                    if (configSnapshot.enableVRDetection && detectedVR == VRPlatform::None) {
                        for (const auto& vrRuntime : VR_RUNTIMES) {
                            for (const auto& processName : vrRuntime.processNames) {
                                if (Utils::StringUtils::IEquals(pe32.szExeFile, processName)) {
                                    detectedVR = vrRuntime.platform;
                                    break;
                                }
                            }
                            if (detectedVR != VRPlatform::None) break;
                        }
                    }

                } while (Process32NextW(hSnapshot.Get(), &pe32));
            }
            // ScopedHandle automatically closes the snapshot
        }
    }

    // Update launcher state
    if (configSnapshot.enableLauncherDetection) {
        for (const auto& launcherDef : LAUNCHER_DATABASE) {
            bool wasRunning = false;
            {
                std::shared_lock lock(m_mutex);
                auto it = m_launchers.find(launcherDef.type);
                if (it != m_launchers.end()) {
                    wasRunning = it->second.isRunning;
                }
            }

            auto& result = launcherResults[launcherDef.type];

            {
                std::unique_lock lock(m_mutex);
                auto& info = m_launchers[launcherDef.type];
                info.isRunning = result.isRunning;
                info.runningPids = std::move(result.runningPids);
            }

            if (result.isRunning != wasRunning) {
                NotifyLauncher(launcherDef.type, result.isRunning);
                m_stats.launcherDetections++;
            }
        }
    }

    // Update VR state
    if (configSnapshot.enableVRDetection) {
        VRPlatform previousVR = m_activeVRPlatform.load(std::memory_order_acquire);
        if (detectedVR != previousVR) {
            m_activeVRPlatform.store(detectedVR, std::memory_order_release);
            if (detectedVR != VRPlatform::None) {
                m_stats.vrDetections++;
                Utils::Logger::Info("[GameProcessDetector] VR platform active: {}", GetVRPlatformName(detectedVR));
            }
        }
    }

    // Check for exited games — also detect PID reuse via creation-time comparison
    std::vector<uint32_t> exitedPids;
    {
        std::shared_lock lock(m_mutex);
        for (const auto& [pid, game] : m_detectedGames) {
            ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!hProcess) {
                exitedPids.push_back(pid);
                continue;
            }

            DWORD exitCode = 0;
            if (GetExitCodeProcess(hProcess.Get(), &exitCode) && exitCode != STILL_ACTIVE) {
                exitedPids.push_back(pid);
                continue;
            }

            // Guard against PID reuse: compare stored creation time
            if (game.processCreationTime.dwLowDateTime != 0 ||
                game.processCreationTime.dwHighDateTime != 0) {
                FILETIME creation{}, exitFt{}, kernel{}, user{};
                if (GetProcessTimes(hProcess.Get(), &creation, &exitFt, &kernel, &user)) {
                    if (creation.dwLowDateTime != game.processCreationTime.dwLowDateTime ||
                        creation.dwHighDateTime != game.processCreationTime.dwHighDateTime) {
                        Utils::Logger::Info("[GameProcessDetector] PID {} reused by different process, treating as exited", pid);
                        exitedPids.push_back(pid);
                    }
                }
            }
        }
    }

    for (uint32_t pid : exitedPids) {
        {
            std::unique_lock lock(m_mutex);
            m_detectedGames.erase(pid);
        }
        NotifyGameExited(pid);
    }

    // Update fullscreen/window state for surviving games
    if (configSnapshot.enableFullscreenDetection) {
        UpdateFullscreenState();
    }
#endif // _WIN32
}

bool GameProcessDetectorImpl::MatchGameDatabase(const std::wstring& processName,
                                               const std::wstring& /*processPath*/,
                                               GameEntry& outEntry) {
    auto it = m_gameDatabase.find(Utils::StringUtils::ToLowerCopy(processName));
    if (it != m_gameDatabase.end()) {
        outEntry = it->second;
        return true;
    }
    return false;
}

bool GameProcessDetectorImpl::MatchWindowClass(HWND hwnd) {
    if (!hwnd) {
        return false;
    }

#ifdef _WIN32
    char className[256] = {};
    GetClassNameA(hwnd, className, sizeof(className));

    for (const auto& gameClass : GAME_WINDOW_CLASSES) {
        if (std::string_view(className).find(gameClass) != std::string_view::npos) {
            return true;
        }
    }
#endif

    return false;
}

bool GameProcessDetectorImpl::IsHeuristicMatch(uint32_t pid, const std::wstring& processPath) {
    // Multi-signal convergence heuristic: require 2+ signals to classify as game.
    // Signals:
    //   1. Process in common game directories
    //   2. Window class matches a known game engine
    //   3. Graphics API modules loaded (d3d11, d3d12, vulkan, opengl)

    int signalCount = 0;

    // Signal 1: Check for common game install directories
    std::wstring lowerPath = Utils::StringUtils::ToLowerCopy(processPath);

    const std::vector<std::wstring> gameDirectories = {
        L"\\steam\\",
        L"\\steamapps\\",
        L"\\epic games\\",
        L"\\origin games\\",
        L"\\gog galaxy\\",
        L"\\ubisoft\\",
        L"\\games\\",
        L"\\program files\\games\\",
        L"\\program files (x86)\\games\\"
    };

    for (const auto& dir : gameDirectories) {
        if (lowerPath.find(dir) != std::wstring::npos) {
            ++signalCount;
            break;
        }
    }

#ifdef _WIN32
    // Signal 2: Check window class via MatchWindowClass (Fix 14: integrating it)
    {
        HWND hwnd = nullptr;
        auto enumData = std::make_pair(pid, &hwnd);
        EnumWindows([](HWND h, LPARAM lParam) -> BOOL {
            auto* data = reinterpret_cast<std::pair<uint32_t, HWND*>*>(lParam);
            DWORD windowPid = 0;
            GetWindowThreadProcessId(h, &windowPid);
            if (windowPid == data->first && IsWindowVisible(h)) {
                *data->second = h;
                return FALSE;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&enumData));

        if (hwnd && MatchWindowClass(hwnd)) {
            ++signalCount;
        }
    }

    // Signal 3: Enumerate loaded modules for graphics API DLLs
    {
        ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (hProcess) {
            HMODULE hMods[512] = {};
            DWORD cbNeeded = 0;

            if (EnumProcessModulesEx(hProcess.Get(), hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
                const DWORD moduleCount = (std::min)(cbNeeded / static_cast<DWORD>(sizeof(HMODULE)),
                                                     static_cast<DWORD>(std::size(hMods)));

                const std::array<std::wstring_view, 4> graphicsModules = {
                    L"d3d11.dll", L"d3d12.dll", L"vulkan-1.dll", L"opengl32.dll"
                };

                for (DWORD i = 0; i < moduleCount; ++i) {
                    wchar_t modName[256] = {};
                    if (GetModuleBaseNameW(hProcess.Get(), hMods[i], modName, static_cast<DWORD>(std::size(modName)))) {
                        for (const auto& gfxMod : graphicsModules) {
                            if (Utils::StringUtils::IEquals(modName, gfxMod)) {
                                ++signalCount;
                                goto done_modules; // Break out of both loops
                            }
                        }
                    }
                }
                done_modules:;
            }
        }
    }
#endif // _WIN32

    // Require 2+ converging signals for heuristic match
    return signalCount >= 2;
}

LauncherType GameProcessDetectorImpl::DetectLauncherFromParent(uint32_t pid) {
#ifdef _WIN32
    // Fix 18: Single-pass iteration to find both parentPid and parentName
    ScopedHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!hSnapshot) {
        return LauncherType::Unknown;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);

    uint32_t parentPid = 0;
    std::wstring parentName;

    // First pass: find parent PID for the target process
    if (Process32FirstW(hSnapshot.Get(), &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot.Get(), &pe32));
    }

    if (parentPid == 0) {
        return LauncherType::Unknown;
    }

    // Single re-traverse to find parent name (same snapshot, no new handle)
    if (Process32FirstW(hSnapshot.Get(), &pe32)) {
        do {
            if (pe32.th32ProcessID == parentPid) {
                parentName = pe32.szExeFile;
                break;
            }
        } while (Process32NextW(hSnapshot.Get(), &pe32));
    }
    // ScopedHandle closes automatically

    if (parentName.empty()) {
        return LauncherType::Unknown;
    }

    // Match against launcher database
    for (const auto& launcher : LAUNCHER_DATABASE) {
        for (const auto& processName : launcher.processNames) {
            if (Utils::StringUtils::IEquals(parentName, processName)) {
                return launcher.type;
            }
        }
    }
#endif

    return LauncherType::Unknown;
}

void GameProcessDetectorImpl::NotifyGameDetected(const DetectedGame& game) {
    DetectedGameCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_gameDetectedCallback;
    }
    if (cb) {
        try {
            cb(game);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[GameProcessDetector] Game detected callback exception: {}", e.what());
        }
    }
}

void GameProcessDetectorImpl::NotifyGameExited(uint32_t pid) {
    GameExitedCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_gameExitedCallback;
    }
    if (cb) {
        try {
            cb(pid);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[GameProcessDetector] Game exited callback exception: {}", e.what());
        }
    }
}

void GameProcessDetectorImpl::NotifyFullscreenChange(bool isFullscreen, const FullscreenInfo& info) {
    FullscreenChangeCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_fullscreenCallback;
    }
    if (cb) {
        try {
            cb(isFullscreen, info);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[GameProcessDetector] Fullscreen callback exception: {}", e.what());
        }
    }
}

void GameProcessDetectorImpl::NotifyLauncher(LauncherType type, bool isRunning) {
    LauncherCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_launcherCallback;
    }
    if (cb) {
        try {
            cb(type, isRunning);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[GameProcessDetector] Launcher callback exception: {}", e.what());
        }
    }
}

void GameProcessDetectorImpl::NotifyError(const std::string& message, int code) {
    ErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCallback;
    }
    if (cb) {
        try {
            cb(message, code);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[GameProcessDetector] Error callback exception: {}", e.what());
        }
    }
}

void GameProcessDetectorImpl::UpdateFullscreenState() {
#ifdef _WIN32
    std::unique_lock lock(m_mutex);
    for (auto& [pid, game] : m_detectedGames) {
        if (!game.windowHandle) {
            continue;
        }

        // Validate window still belongs to the expected process
        DWORD windowPid = 0;
        GetWindowThreadProcessId(game.windowHandle, &windowPid);
        if (windowPid != pid) {
            game.windowHandle = nullptr;
            game.windowState = WindowState::Unknown;
            game.isFullscreen = false;
            continue;
        }

        game.windowState = GetWindowState(game.windowHandle);
        bool wasFullscreen = game.isFullscreen;
        game.isFullscreen = (game.windowState == WindowState::ExclusiveFullscreen ||
                             game.windowState == WindowState::BorderlessWindowed);
        game.isForeground = (GetForegroundWindow() == game.windowHandle);

        if (game.isFullscreen != wasFullscreen) {
            Utils::Logger::Debug("[GameProcessDetector] Fullscreen state changed for PID {}: {}",
                pid, game.isFullscreen ? "fullscreen" : "windowed");
        }
    }
#endif
}

std::wstring GameProcessDetectorImpl::GetProcessPath(uint32_t pid) {
#ifdef _WIN32
    ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!hProcess) {
        return L"";
    }

    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess.Get(), 0, path, &size)) {
        return path;
    }
#endif
    return L"";
}

std::string GameProcessDetectorImpl::GetWindowTitle(HWND hwnd) {
    if (!hwnd) {
        return "";
    }

#ifdef _WIN32
    char title[256] = {};
    GetWindowTextA(hwnd, title, sizeof(title));
    return title;
#else
    return "";
#endif
}

bool GameProcessDetectorImpl::SelfTest() {
    Utils::Logger::Info("[GameProcessDetector] Running self-test...");

    try {
        // Test 1: Database integrity
        {
            if (m_gameDatabase.empty()) {
                Utils::Logger::Error("[GameProcessDetector] Self-test failed: Empty game database");
                return false;
            }
        }

        // Test 2: Launcher database
        {
            if (LAUNCHER_DATABASE.empty()) {
                Utils::Logger::Error("[GameProcessDetector] Self-test failed: Empty launcher database");
                return false;
            }
        }

        // Test 3: Process name matching
        {
            if (!IsKnownGame(L"Cyberpunk2077.exe")) {
                Utils::Logger::Error("[GameProcessDetector] Self-test failed: Known game not recognized");
                return false;
            }
        }

        // Test 4: Window state detection
        {
            WindowState state = GetWindowState(nullptr);
            if (state != WindowState::Unknown) {
                Utils::Logger::Error("[GameProcessDetector] Self-test failed: Invalid window state for null handle");
                return false;
            }
        }

        Utils::Logger::Info("[GameProcessDetector] Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("[GameProcessDetector] Self-test exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> GameProcessDetector::s_instanceCreated{false};

GameProcessDetector::GameProcessDetector()
    : m_impl(std::make_unique<GameProcessDetectorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

GameProcessDetector::~GameProcessDetector() = default;

GameProcessDetector& GameProcessDetector::Instance() noexcept {
    static GameProcessDetector instance;
    return instance;
}

bool GameProcessDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// PUBLIC API FORWARDING
// ============================================================================

bool GameProcessDetector::Initialize(const DetectorConfiguration& config) {
    return m_impl->Initialize(config);
}

void GameProcessDetector::Shutdown() {
    m_impl->Shutdown();
}

bool GameProcessDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

DetectorStatus GameProcessDetector::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool GameProcessDetector::UpdateConfiguration(const DetectorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

DetectorConfiguration GameProcessDetector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

bool GameProcessDetector::IsGameProcess(uint32_t pid) {
    return m_impl->IsGameProcess(pid);
}

bool GameProcessDetector::IsKnownGame(const std::wstring& processName) {
    return m_impl->IsKnownGame(processName);
}

std::optional<DetectedGame> GameProcessDetector::DetectGame(uint32_t pid) {
    return m_impl->DetectGame(pid);
}

std::vector<DetectedGame> GameProcessDetector::GetDetectedGames() const {
    return m_impl->GetDetectedGames();
}

bool GameProcessDetector::IsAnyGameRunning() const noexcept {
    return m_impl->IsAnyGameRunning();
}

bool GameProcessDetector::IsForegroundFullscreen() {
    return m_impl->IsForegroundFullscreen();
}

FullscreenInfo GameProcessDetector::GetFullscreenInfo() {
    return m_impl->GetFullscreenInfo();
}

bool GameProcessDetector::IsWindowFullscreen(HWND hwnd) {
    return m_impl->IsWindowFullscreen(hwnd);
}

WindowState GameProcessDetector::GetWindowState(HWND hwnd) {
    return m_impl->GetWindowState(hwnd);
}

std::vector<LauncherInfo> GameProcessDetector::GetRunningLaunchers() const {
    return m_impl->GetRunningLaunchers();
}

bool GameProcessDetector::IsLauncherRunning(LauncherType type) const {
    return m_impl->IsLauncherRunning(type);
}

std::optional<LauncherInfo> GameProcessDetector::GetLauncherInfo(LauncherType type) const {
    return m_impl->GetLauncherInfo(type);
}

bool GameProcessDetector::IsVRActive() const noexcept {
    return m_impl->IsVRActive();
}

VRPlatform GameProcessDetector::GetActiveVRPlatform() const noexcept {
    return m_impl->GetActiveVRPlatform();
}

bool GameProcessDetector::LoadDatabase(const std::wstring& path) {
    return m_impl->LoadDatabase(path);
}

size_t GameProcessDetector::GetDatabaseSize() const noexcept {
    return m_impl->GetDatabaseSize();
}

std::vector<GameEntry> GameProcessDetector::SearchDatabase(const std::string& query, size_t limit) {
    return m_impl->SearchDatabase(query, limit);
}

bool GameProcessDetector::AddUserGame(const std::wstring& processName, const std::string& title) {
    return m_impl->AddUserGame(processName, title);
}

bool GameProcessDetector::RemoveUserGame(const std::wstring& processName) {
    return m_impl->RemoveUserGame(processName);
}

void GameProcessDetector::RegisterGameDetectedCallback(DetectedGameCallback callback) {
    m_impl->RegisterGameDetectedCallback(std::move(callback));
}

void GameProcessDetector::RegisterGameExitedCallback(GameExitedCallback callback) {
    m_impl->RegisterGameExitedCallback(std::move(callback));
}

void GameProcessDetector::RegisterFullscreenChangeCallback(FullscreenChangeCallback callback) {
    m_impl->RegisterFullscreenChangeCallback(std::move(callback));
}

void GameProcessDetector::RegisterLauncherCallback(LauncherCallback callback) {
    m_impl->RegisterLauncherCallback(std::move(callback));
}

void GameProcessDetector::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void GameProcessDetector::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

DetectorStatistics GameProcessDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void GameProcessDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool GameProcessDetector::SelfTest() {
    return m_impl->SelfTest();
}

std::string GameProcessDetector::GetVersionString() {
    return std::to_string(DetectorConstants::VERSION_MAJOR) + "." +
           std::to_string(DetectorConstants::VERSION_MINOR) + "." +
           std::to_string(DetectorConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE SERIALIZATION
// ============================================================================

void DetectorStatistics::Reset() noexcept {
    gamesDetected.store(0, std::memory_order_release);
    fullscreenDetections.store(0, std::memory_order_release);
    launcherDetections.store(0, std::memory_order_release);
    vrDetections.store(0, std::memory_order_release);
    falsePositives.store(0, std::memory_order_release);
    processesScanned.store(0, std::memory_order_release);
    databaseLookups.store(0, std::memory_order_release);
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string DetectorStatistics::ToJson() const {
    nlohmann::json j;
    j["gamesDetected"] = gamesDetected.load(std::memory_order_acquire);
    j["fullscreenDetections"] = fullscreenDetections.load(std::memory_order_acquire);
    j["launcherDetections"] = launcherDetections.load(std::memory_order_acquire);
    j["vrDetections"] = vrDetections.load(std::memory_order_acquire);
    j["falsePositives"] = falsePositives.load(std::memory_order_acquire);
    j["processesScanned"] = processesScanned.load(std::memory_order_acquire);
    j["databaseLookups"] = databaseLookups.load(std::memory_order_acquire);

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - AtomicValueLoadRelaxed(startTime)).count();
    j["uptimeSeconds"] = elapsed;

    return j.dump();
}

std::string GameEntry::ToJson() const {
    nlohmann::json j;
    j["gameId"] = gameId;
    j["title"] = title;
    j["publisher"] = publisher;
    j["category"] = static_cast<int>(category);
    j["launcher"] = static_cast<int>(launcher);
    j["isVR"] = isVR;
    j["requiresElevatedPerformance"] = requiresElevatedPerformance;
    return j.dump();
}

std::string DetectedGame::ToJson() const {
    nlohmann::json j;
    j["processId"] = processId;
    j["processName"] = Utils::StringUtils::WStringToString(processName);
    j["windowTitle"] = windowTitle;
    j["detectionMethod"] = static_cast<int>(detectionMethod);
    j["windowState"] = static_cast<int>(windowState);
    j["launcherType"] = static_cast<int>(launcherType);
    j["isForeground"] = isForeground;
    j["isFullscreen"] = isFullscreen;
    j["confidence"] = confidence;
    return j.dump();
}

std::string LauncherInfo::ToJson() const {
    nlohmann::json j;
    j["type"] = static_cast<int>(type);
    j["displayName"] = displayName;
    j["isRunning"] = isRunning;
    j["runningPidCount"] = runningPids.size();
    return j.dump();
}

std::string FullscreenInfo::ToJson() const {
    nlohmann::json j;
    j["hasFullscreenApp"] = hasFullscreenApp;
    j["processId"] = processId;
    j["windowState"] = static_cast<int>(windowState);
    j["resolutionWidth"] = resolutionWidth;
    j["resolutionHeight"] = resolutionHeight;
    j["refreshRate"] = refreshRate;
    j["isHDRActive"] = isHDRActive;
    return j.dump();
}

void DetectedGame::RefreshWindowHandle() {
#ifdef _WIN32
    if (processId == 0) {
        windowHandle = nullptr;
        return;
    }

    HWND found = nullptr;
    auto enumData = std::make_pair(processId, &found);
    EnumWindows([](HWND h, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<std::pair<uint32_t, HWND*>*>(lParam);
        DWORD windowPid = 0;
        GetWindowThreadProcessId(h, &windowPid);
        if (windowPid == data->first && IsWindowVisible(h)) {
            *data->second = h;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&enumData));

    windowHandle = found;
#endif
}

bool DetectorConfiguration::IsValid() const noexcept {
    if (pollIntervalMs == 0 || pollIntervalMs > 60000) {
        return false;
    }
    if (confidenceThreshold > 100) {
        return false;
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetCategoryName(GameCategory category) noexcept {
    switch (category) {
        case GameCategory::AAA:         return "AAA";
        case GameCategory::Indie:       return "Indie";
        case GameCategory::FreeToPlay:  return "FreeToPlay";
        case GameCategory::Emulator:    return "Emulator";
        case GameCategory::VR:          return "VR";
        case GameCategory::Casual:      return "Casual";
        case GameCategory::Browser:     return "Browser";
        default:                        return "Unknown";
    }
}

std::string_view GetLauncherTypeName(LauncherType type) noexcept {
    switch (type) {
        case LauncherType::Steam:       return "Steam";
        case LauncherType::Epic:        return "Epic Games";
        case LauncherType::Origin:      return "Origin/EA";
        case LauncherType::GOG:         return "GOG Galaxy";
        case LauncherType::Battlenet:   return "Battle.net";
        case LauncherType::Ubisoft:     return "Ubisoft Connect";
        case LauncherType::Xbox:        return "Xbox Game Pass";
        case LauncherType::Amazon:      return "Amazon Games";
        case LauncherType::RiotClient:  return "Riot Client";
        case LauncherType::Rockstar:    return "Rockstar Games";
        case LauncherType::Bethesda:    return "Bethesda.net";
        case LauncherType::Custom:      return "Custom";
        default:                        return "Unknown";
    }
}

std::string_view GetWindowStateName(WindowState state) noexcept {
    switch (state) {
        case WindowState::Windowed:            return "Windowed";
        case WindowState::BorderlessWindowed:  return "BorderlessWindowed";
        case WindowState::ExclusiveFullscreen: return "ExclusiveFullscreen";
        case WindowState::Minimized:           return "Minimized";
        default:                               return "Unknown";
    }
}

std::string_view GetDetectionMethodName(DetectionMethod method) noexcept {
    switch (method) {
        case DetectionMethod::ProcessName:       return "ProcessName";
        case DetectionMethod::WindowTitle:       return "WindowTitle";
        case DetectionMethod::ParentProcess:     return "ParentProcess";
        case DetectionMethod::DigitalSignature:  return "DigitalSignature";
        case DetectionMethod::DirectoryPath:     return "DirectoryPath";
        case DetectionMethod::RegistryKey:       return "RegistryKey";
        case DetectionMethod::WindowClass:       return "WindowClass";
        case DetectionMethod::Heuristic:         return "Heuristic";
        default:                                 return "Unknown";
    }
}

std::string_view GetVRPlatformName(VRPlatform platform) noexcept {
    switch (platform) {
        case VRPlatform::SteamVR:        return "SteamVR";
        case VRPlatform::OculusRuntime:  return "Oculus Runtime";
        case VRPlatform::WindowsMR:      return "Windows Mixed Reality";
        case VRPlatform::OpenXR:         return "OpenXR";
        default:                         return "None";
    }
}

std::wstring GetLauncherInstallPath(LauncherType type) {
    // Try registry lookup
    for (const auto& launcher : LAUNCHER_DATABASE) {
        if (launcher.type == type && !launcher.registryPath.empty()) {
#ifdef _WIN32
            // HKLM
            {
                ScopedRegKey hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, launcher.registryPath.c_str(),
                                 0, KEY_READ, hKey.Put()) == ERROR_SUCCESS) {
                    wchar_t buffer[MAX_PATH] = {};
                    DWORD bufferSize = sizeof(buffer);
                    if (RegQueryValueExW(hKey.Get(), launcher.registryValue.c_str(), nullptr,
                                        nullptr, reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
                        return buffer;
                    }
                }
            }

            // HKCU
            {
                ScopedRegKey hKey;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, launcher.registryPath.c_str(),
                                 0, KEY_READ, hKey.Put()) == ERROR_SUCCESS) {
                    wchar_t buffer[MAX_PATH] = {};
                    DWORD bufferSize = sizeof(buffer);
                    if (RegQueryValueExW(hKey.Get(), launcher.registryValue.c_str(), nullptr,
                                        nullptr, reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
                        return buffer;
                    }
                }
            }
#endif
        }
    }

    return L"";
}

LauncherType DetectLauncherFromProcess(uint32_t pid) {
    auto& detector = GameProcessDetector::Instance();
    if (!detector.IsInitialized()) {
        return LauncherType::Unknown;
    }

    // This is handled internally by DetectGame
    auto game = detector.DetectGame(pid);
    if (game) {
        return game->launcherType;
    }

    return LauncherType::Unknown;
}

}  // namespace GameMode
}  // namespace ShadowStrike
