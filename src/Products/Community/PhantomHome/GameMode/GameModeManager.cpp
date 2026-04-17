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
 * ShadowStrike NGAV - GAME MODE MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file GameModeManager.cpp
 * @brief Enterprise-grade game mode orchestration with automatic detection
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
#include "GameModeManager.hpp"
#include "PerformanceOptimizer.hpp"
#include "OverlayProtection.hpp"
#include "GameProcessDetector.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/SystemUtils.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <regex>
#include <cmath>
#include <deque>
#include <thread>
#include <condition_variable>
#include <cstdio>
#include <format>

#pragma comment(lib, "Psapi.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace GameMode {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> GameModeManager::s_instanceCreated{false};

// ============================================================================
// INTERNAL STRUCTURES & HELPERS
// ============================================================================

namespace {

// ---- Fix #18: RAII wrapper for Win32 HANDLE from snapshot APIs ----
class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
        : m_handle(handle) {}

    ~ScopedHandle() noexcept {
        if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
            ::CloseHandle(m_handle);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept
        : m_handle(other.m_handle) {
        other.m_handle = INVALID_HANDLE_VALUE;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
                ::CloseHandle(m_handle);
            }
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    [[nodiscard]] bool IsValid() const noexcept {
        return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
    }
    [[nodiscard]] explicit operator bool() const noexcept { return IsValid(); }

private:
    HANDLE m_handle;
};

// ---- Fix #12: Blocklist for non-game fullscreen processes ----
const std::vector<std::wstring> FULLSCREEN_BLOCKLIST = {
    L"explorer.exe",
    L"chrome.exe",
    L"firefox.exe",
    L"msedge.exe",
    L"Code.exe",
    L"devenv.exe",
    L"Teams.exe",
    L"Taskmgr.exe",
    L"mstsc.exe",
    L"vlc.exe",
    L"wmplayer.exe",
    L"Spotify.exe",
    L"slack.exe",
    L"Zoom.exe",
    L"Opera.exe",
    L"brave.exe",
    L"iexplore.exe",
    L"powershell.exe",
    L"WindowsTerminal.exe",
    L"cmd.exe",
    L"SystemSettings.exe",
    L"ApplicationFrameHost.exe",
    L"ShellExperienceHost.exe",
    L"SearchHost.exe",
    L"StartMenuExperienceHost.exe",
    L"RuntimeBroker.exe"
};

// ---- Fix #21: Fullscreen hysteresis constants ----
inline constexpr uint32_t FULLSCREEN_CONSECUTIVE_THRESHOLD = 2;
inline constexpr uint32_t FULLSCREEN_COOLDOWN_SECONDS = 60;

/// @brief Generate unique session ID
/// L2-FIX: Mix in PID and high-resolution clock for unpredictable session IDs.
std::string GenerateSessionId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    auto pid = ::GetCurrentProcessId();
    auto seq = counter.fetch_add(1, std::memory_order_relaxed);
    return std::format("GS-{:X}-{:X}-{:04X}", now ^ pid, pid, seq & 0xFFFF);
}

/// @brief Generate unique action ID
std::string GenerateActionId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << "ACT-" << std::hex << std::setw(12) << std::setfill('0') << ms
        << "-" << std::setw(6) << std::setfill('0') << counter.fetch_add(1);
    return oss.str();
}

/// @brief Known game launchers
const std::vector<std::wstring> KNOWN_LAUNCHERS = {
    L"Steam.exe",
    L"EpicGamesLauncher.exe",
    L"Origin.exe",
    L"Battle.net.exe",
    L"uplay.exe",
    L"GalaxyClient.exe",
    L"Bethesda.net_Launcher.exe",
    L"RockstarGames.exe",
    L"EADesktop.exe"
};

/// @brief Known VR applications
const std::vector<std::wstring> VR_APPLICATIONS = {
    L"vrserver.exe",
    L"vrstartup.exe",
    L"OculusClient.exe",
    L"ViveportDesktop.exe",
    L"WMRRegistration.exe"
};

/// @brief Known streaming applications
const std::vector<std::wstring> STREAMING_APPS = {
    L"obs64.exe",
    L"obs32.exe",
    L"XSplit.Core.exe",
    L"streamlabs obs.exe",
    L"Discord.exe"
};

/// @brief Check if process is fullscreen
bool IsProcessFullscreen(uint32_t pid) {
    HWND hwnd = nullptr;

    // Find main window for process
    auto callback = [](HWND window, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<std::pair<uint32_t, HWND*>*>(lParam);

        DWORD windowPid = 0;
        GetWindowThreadProcessId(window, &windowPid);

        if (windowPid == data->first && IsWindowVisible(window)) {
            // Fix #16: Use GetWindowLongPtrW instead of GetWindowLong
            LONG_PTR style = GetWindowLongPtrW(window, GWL_STYLE);
            if (style & WS_VISIBLE) {
                *(data->second) = window;
                return FALSE;
            }
        }
        return TRUE;
    };

    std::pair<uint32_t, HWND*> data{pid, &hwnd};
    EnumWindows(callback, reinterpret_cast<LPARAM>(&data));

    if (!hwnd) return false;

    // Check if fullscreen
    RECT windowRect;
    if (!GetWindowRect(hwnd, &windowRect)) return false;

    HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo = {sizeof(MONITORINFO)};

    if (!GetMonitorInfo(monitor, &monitorInfo)) return false;

    // Check if window covers entire monitor
    return (windowRect.left <= monitorInfo.rcMonitor.left &&
            windowRect.top <= monitorInfo.rcMonitor.top &&
            windowRect.right >= monitorInfo.rcMonitor.right &&
            windowRect.bottom >= monitorInfo.rcMonitor.bottom);
}

/// @brief Check if process name is in the fullscreen blocklist (case-insensitive)
bool IsBlocklistedProcess(const std::wstring& processName) {
    for (const auto& blocked : FULLSCREEN_BLOCKLIST) {
        if (_wcsicmp(processName.c_str(), blocked.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

/// @brief Get current time in minutes from midnight
uint16_t GetCurrentMinutesFromMidnight() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm localTime;
    localtime_s(&localTime, &time);

    return static_cast<uint16_t>(localTime.tm_hour * 60 + localTime.tm_min);
}

/// @brief Get current day of week (0 = Sunday)
uint8_t GetCurrentDayOfWeek() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm localTime;
    localtime_s(&localTime, &time);

    return static_cast<uint8_t>(localTime.tm_wday);
}

} // anonymous namespace

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

std::string GameSession::ToJson() const {
    json j;
    j["sessionId"] = sessionId;
    j["processId"] = processId;
    j["processName"] = Utils::StringUtils::WStringToString(processName);
    j["gameTitle"] = gameTitle;
    j["reason"] = static_cast<int>(reason);
    j["startedTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        startedTime.time_since_epoch()).count();

    if (endedTime.has_value()) {
        j["endedTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            endedTime->time_since_epoch()).count();
    }

    j["durationSeconds"] = durationSeconds;
    j["threatsBlocked"] = threatsBlocked;
    j["actionsDeferred"] = actionsDeferred;

    return j.dump();
}

std::string DeferredAction::ToJson() const {
    json j;
    j["actionId"] = actionId;
    j["actionType"] = static_cast<int>(actionType);
    j["description"] = description;
    j["deferredTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        deferredTime.time_since_epoch()).count();
    j["priority"] = priority;

    json contextJson;
    for (const auto& [key, value] : context) {
        contextJson[key] = value;
    }
    j["context"] = contextJson;

    return j.dump();
}

std::string GameModeProfile::ToJson() const {
    json j;
    j["name"] = name;
    j["description"] = description;
    j["protectionLevel"] = static_cast<int>(protectionLevel);
    j["resourcePriority"] = static_cast<int>(resourcePriority);
    j["notificationPolicy"] = static_cast<int>(notificationPolicy);
    j["postponeScans"] = postponeScans;
    j["postponeUpdates"] = postponeUpdates;
    j["reduceRealtimeScan"] = reduceRealtimeScan;
    j["criticalAlertsOnly"] = criticalAlertsOnly;
    j["enableOverlayProtection"] = enableOverlayProtection;
    j["autoDisableMinutes"] = autoDisableMinutes;
    j["isDefault"] = isDefault;
    return j.dump();
}

// Fix #20: Treat startMinutes == endMinutes as 24-hour schedule ("always active")
bool GameModeSchedule::IsActiveNow() const {
    if (!enabled) return false;

    uint8_t currentDay = GetCurrentDayOfWeek();
    uint16_t currentMinutes = GetCurrentMinutesFromMidnight();

    // Check day of week
    uint8_t dayBit = (1 << currentDay);
    if (!(daysOfWeek & dayBit)) return false;

    // Edge case: startMinutes == endMinutes means 24-hour schedule
    if (startMinutes == endMinutes) {
        return true;
    }

    // Check time range
    if (startMinutes < endMinutes) {
        // Normal range (e.g., 9:00 to 17:00)
        return currentMinutes >= startMinutes && currentMinutes < endMinutes;
    } else {
        // Overnight range (e.g., 22:00 to 2:00)
        return currentMinutes >= startMinutes || currentMinutes < endMinutes;
    }
}

std::string GameModeSchedule::ToJson() const {
    json j;
    j["ruleId"] = ruleId;
    j["name"] = name;
    j["daysOfWeek"] = daysOfWeek;
    j["startMinutes"] = startMinutes;
    j["endMinutes"] = endMinutes;
    j["profileName"] = profileName;
    j["enabled"] = enabled;
    return j.dump();
}

void GameModeStatistics::Reset() noexcept {
    totalSessions = 0;
    totalDurationSeconds = 0;
    autoActivations = 0;
    manualActivations = 0;
    threatsBlocked = 0;
    actionsDeferred = 0;
    scansPostponed = 0;
    notificationsSuppressed = 0;
    startTime = Clock::now();
}

std::string GameModeStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    json j;
    j["uptimeSeconds"] = uptime;
    j["totalSessions"] = totalSessions.load();
    j["totalDurationSeconds"] = totalDurationSeconds.load();
    j["autoActivations"] = autoActivations.load();
    j["manualActivations"] = manualActivations.load();
    j["threatsBlocked"] = threatsBlocked.load();
    j["actionsDeferred"] = actionsDeferred.load();
    j["scansPostponed"] = scansPostponed.load();
    j["notificationsSuppressed"] = notificationsSuppressed.load();
    return j.dump();
}

bool GameModeConfiguration::IsValid() const noexcept {
    if (detectionIntervalMs == 0 || detectionIntervalMs > 60000) {
        return false;
    }

    if (autoDisableHours > 24) {
        return false;
    }

    if (resumeDelaySeconds > 3600) {
        return false;
    }

    if (defaultProfile.empty()) {
        return false;
    }

    return true;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class GameModeManagerImpl final {
public:
    GameModeManagerImpl();
    ~GameModeManagerImpl();

    // Lifecycle
    bool Initialize(const GameModeConfiguration& config);
    void Shutdown();
    // Fix #14: IsInitialized returns true when status is Inactive or Active
    bool IsInitialized() const noexcept {
        auto status = m_status.load(std::memory_order_acquire);
        return status == GameModeStatus::Inactive || status == GameModeStatus::Active;
    }
    GameModeStatus GetStatus() const noexcept { return m_status; }
    bool UpdateConfiguration(const GameModeConfiguration& config);
    GameModeConfiguration GetConfiguration() const;

    // Game mode control
    void SetEnabled(bool enabled);
    // Fix #11: Add ActivationReason parameter
    bool Activate(const std::string& profileName,
                  ActivationReason reason = ActivationReason::Manual);
    void Deactivate();
    bool IsActive() const noexcept { return m_gameModeActive; }
    ActivationReason GetActivationReason() const noexcept { return m_activationReason; }
    ProtectionLevel GetProtectionLevel() const noexcept;
    void OnGameStateChanged(bool isGaming);
    void OnGameDetected(uint32_t pid, const std::wstring& processName);
    void OnGameExited(uint32_t pid);

    // Profile management
    std::vector<GameModeProfile> GetProfiles() const;
    std::optional<GameModeProfile> GetProfile(const std::string& name) const;
    bool SaveProfile(const GameModeProfile& profile);
    bool DeleteProfile(const std::string& name);
    bool SetDefaultProfile(const std::string& name);

    // Scheduling
    std::vector<GameModeSchedule> GetSchedules() const;
    bool SaveSchedule(const GameModeSchedule& schedule);
    bool DeleteSchedule(const std::string& ruleId);
    bool IsScheduledNow() const;

    // Action deferral
    void DeferAction(const DeferredAction& action);
    std::vector<DeferredAction> GetDeferredActions() const;
    void ExecuteDeferredActions();
    void ClearDeferredActions();

    // Session history
    std::optional<GameSession> GetCurrentSession() const;
    std::vector<GameSession> GetSessionHistory(size_t limit) const;

    // Utility checks
    bool ShouldShowNotification(uint8_t severity) const;
    bool ShouldDeferScan() const;
    bool ShouldDeferUpdate() const;

    // Callbacks
    void RegisterStateChangeCallback(StateChangeCallback callback);
    void RegisterGameDetectedCallback(GameDetectedCallback callback);
    void RegisterActionDeferredCallback(ActionDeferredCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void RegisterActionDispatcher(ActionDispatcherCallback dispatcher);
    void UnregisterCallbacks();

    // Statistics
    GameModeStatistics GetStatistics() const;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal methods
    void DetectionThreadFunc();
    void ScheduleCheckThreadFunc();
    void ApplyProfile(const GameModeProfile& profile);
    void RestoreNormalMode();
    bool DetectGames();
    bool DetectFullscreenApps();
    bool DetectLaunchers();
    bool DetectVRApps();
    bool DetectStreamingApps();
    void NotifyStateChange(bool active, ActivationReason reason);
    void NotifyError(const std::string& message, int code);
    void CreateDefaultProfiles();
    void EndCurrentSession();

    // Fix #10: Internal deactivation that assumes m_mutex is already held exclusively
    void DeactivateCore_Locked();

    // Managed resume-worker thread used to run ExecuteDeferredActions() after
    // the configured resume delay. Replaces prior detached std::threads so the
    // object lifetime is bounded and UAF is impossible.
    void ResumeWorkerThreadFunc();
    void ScheduleDeferredResume(uint32_t delaySeconds);

    // Member variables
    mutable std::shared_mutex m_mutex;
    // Fix #14: Renamed from m_isActive to m_initialized for clarity
    std::atomic<bool> m_initialized{false};
    std::atomic<GameModeStatus> m_status{GameModeStatus::Uninitialized};
    GameModeConfiguration m_config;

    // Game mode state
    std::atomic<bool> m_gameModeActive{false};
    std::atomic<ActivationReason> m_activationReason{ActivationReason::Manual};
    GameModeProfile m_currentProfile;

    // Profiles
    std::unordered_map<std::string, GameModeProfile> m_profiles;

    // Schedules
    std::vector<GameModeSchedule> m_schedules;

    // Sessions
    std::optional<GameSession> m_currentSession;
    // Fix #15: Changed from std::vector to std::deque for O(1) push_front
    std::deque<GameSession> m_sessionHistory;

    // Deferred actions
    std::vector<DeferredAction> m_deferredActions;

    // Detection thread
    std::unique_ptr<std::thread> m_detectionThread;
    std::atomic<bool> m_stopDetection{false};

    // Schedule thread
    std::unique_ptr<std::thread> m_scheduleThread;
    std::atomic<bool> m_stopSchedule{false};

    // Resume worker: single managed thread that executes deferred actions
    // after a configured delay. Joined in Shutdown to guarantee lifetime
    // safety (no detached threads).
    std::unique_ptr<std::thread> m_resumeThread;
    std::atomic<bool> m_stopResume{false};
    std::mutex m_resumeMutex;
    std::condition_variable m_resumeCv;
    std::optional<TimePoint> m_pendingResumeDeadline;

    // Callbacks
    StateChangeCallback m_stateChangeCallback;
    GameDetectedCallback m_gameDetectedCallback;
    ActionDeferredCallback m_actionDeferredCallback;
    ErrorCallback m_errorCallback;
    ActionDispatcherCallback m_actionDispatcher;

    // Statistics
    GameModeStatistics m_stats;

    // Auto-disable timer
    std::optional<SystemTimePoint> m_autoDisableTime;

    // Fix #21: Fullscreen detection hysteresis state
    std::atomic<uint32_t> m_consecutiveFullscreenCount{0};
    TimePoint m_lastFullscreenDeactivation{};

    // H1: Launcher detected flag (does not activate game mode by itself)
    std::atomic<bool> m_launcherDetected{false};
};

// ============================================================================
// PIMPL CONSTRUCTOR/DESTRUCTOR
// ============================================================================

GameModeManagerImpl::GameModeManagerImpl() {
    Utils::Logger::Info("GameModeManagerImpl constructed");
}

GameModeManagerImpl::~GameModeManagerImpl() {
    Shutdown();
    Utils::Logger::Info("GameModeManagerImpl destroyed");
}

// ============================================================================
// LIFECYCLE IMPLEMENTATION
// ============================================================================

bool GameModeManagerImpl::Initialize(const GameModeConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (m_initialized) {
            Utils::Logger::Warn("GameModeManager already initialized");
            return false;
        }

        m_status = GameModeStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid GameModeManager configuration");
            m_status = GameModeStatus::Error;
            return false;
        }

        m_config = config;

        // Create default profiles
        CreateDefaultProfiles();

        // Initialize statistics
        m_stats.Reset();

        // Start detection thread if auto-detection enabled
        if (m_config.autoDetectionEnabled) {
            m_stopDetection = false;
            m_detectionThread = std::make_unique<std::thread>(
                &GameModeManagerImpl::DetectionThreadFunc, this);
        }

        // Start schedule check thread
        m_stopSchedule = false;
        m_scheduleThread = std::make_unique<std::thread>(
            &GameModeManagerImpl::ScheduleCheckThreadFunc, this);

        // Start resume worker thread (used to run deferred actions after
        // the configured resume delay without detaching).
        m_stopResume.store(false, std::memory_order_release);
        {
            std::lock_guard lk(m_resumeMutex);
            m_pendingResumeDeadline.reset();
        }
        m_resumeThread = std::make_unique<std::thread>(
            &GameModeManagerImpl::ResumeWorkerThreadFunc, this);

        m_initialized = true;
        m_status = GameModeStatus::Inactive;

        Utils::Logger::Info("GameModeManager initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Fatal("GameModeManager initialization failed: {}", e.what());

        // Stop any threads that were launched before the exception
        m_stopDetection.store(true, std::memory_order_release);
        m_stopSchedule.store(true, std::memory_order_release);
        m_stopResume.store(true, std::memory_order_release);
        m_resumeCv.notify_all();

        // Move threads out before unlocking so we can join outside the lock
        auto detThread = std::move(m_detectionThread);
        auto schThread = std::move(m_scheduleThread);
        auto resThread = std::move(m_resumeThread);

        lock.unlock();

        if (detThread && detThread->joinable()) detThread->join();
        if (schThread && schThread->joinable()) schThread->join();
        if (resThread && resThread->joinable()) resThread->join();

        m_status = GameModeStatus::Error;
        return false;
    }
}

// Fix #6: Shutdown restructured to avoid deadlock.
// Set stop flags BEFORE lock. Join threads OUTSIDE lock. Only hold lock for state cleanup.
void GameModeManagerImpl::Shutdown() {
    // Check early without lock - avoid work if not initialized
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_status = GameModeStatus::Stopping;

    // Set stop flags BEFORE acquiring the lock so threads can observe them
    m_stopDetection.store(true, std::memory_order_release);
    m_stopSchedule.store(true, std::memory_order_release);
    m_stopResume.store(true, std::memory_order_release);
    m_resumeCv.notify_all();

    // Join threads OUTSIDE the lock to prevent deadlock
    // (threads may need the lock to check state during wind-down)
    std::unique_ptr<std::thread> detectionThread;
    std::unique_ptr<std::thread> scheduleThread;
    std::unique_ptr<std::thread> resumeThread;

    {
        std::unique_lock lock(m_mutex);
        detectionThread = std::move(m_detectionThread);
        scheduleThread = std::move(m_scheduleThread);
        resumeThread = std::move(m_resumeThread);
    }

    try {
        if (detectionThread && detectionThread->joinable()) {
            detectionThread->join();
        }
    } catch (const std::exception& e) {
        Utils::Logger::Error("Detection thread join failed: {}", e.what());
    }

    try {
        if (scheduleThread && scheduleThread->joinable()) {
            scheduleThread->join();
        }
    } catch (const std::exception& e) {
        Utils::Logger::Error("Schedule thread join failed: {}", e.what());
    }

    try {
        if (resumeThread && resumeThread->joinable()) {
            resumeThread->join();
        }
    } catch (const std::exception& e) {
        Utils::Logger::Error("Resume thread join failed: {}", e.what());
    }

    // Deactivate if active (outside lock, Deactivate handles its own locking)
    if (m_gameModeActive.load(std::memory_order_acquire)) {
        Deactivate();
    }

    // Execute remaining deferred actions
    ExecuteDeferredActions();

    // Now take lock for final state cleanup
    {
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        m_status = GameModeStatus::Uninitialized;
    }

    Utils::Logger::Info("GameModeManager shutdown complete");
}

bool GameModeManagerImpl::UpdateConfiguration(const GameModeConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid configuration");
            return false;
        }

        m_config = config;

        Utils::Logger::Info("Configuration updated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UpdateConfiguration failed: {}", e.what());
        return false;
    }
}

GameModeConfiguration GameModeManagerImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// GAME MODE CONTROL IMPLEMENTATION
// ============================================================================

void GameModeManagerImpl::SetEnabled(bool enabled) {
    std::unique_lock lock(m_mutex);
    m_config.enabled = enabled;

    if (!enabled && m_gameModeActive) {
        lock.unlock();
        Deactivate();
    }

    Utils::Logger::Info("Game mode {}", enabled ? "enabled" : "disabled");
}

// Fix #11: Activate now accepts ActivationReason parameter
bool GameModeManagerImpl::Activate(const std::string& profileName,
                                    ActivationReason reason) {
    try {
        std::unique_lock lock(m_mutex);

        if (m_gameModeActive) {
            Utils::Logger::Warn("Game mode already active");
            return false;
        }

        if (!m_config.enabled) {
            Utils::Logger::Warn("Game mode is disabled");
            return false;
        }

        m_status = GameModeStatus::Transitioning;

        // Get profile
        std::string targetProfile = profileName.empty() ? m_config.defaultProfile : profileName;
        auto profileIt = m_profiles.find(targetProfile);

        if (profileIt == m_profiles.end()) {
            Utils::Logger::Error("Profile not found: {}", targetProfile);
            m_status = GameModeStatus::Inactive;
            return false;
        }

        m_currentProfile = profileIt->second;

        // Create session
        GameSession session;
        session.sessionId = GenerateSessionId();
        session.startedTime = std::chrono::system_clock::now();
        session.reason = reason;
        session.gameTitle = (reason == ActivationReason::Manual)
                            ? "Manual Activation"
                            : "Auto Activation";

        m_currentSession = session;

        // Apply profile settings
        ApplyProfile(m_currentProfile);

        // Set auto-disable timer
        if (m_currentProfile.autoDisableMinutes > 0) {
            auto now = std::chrono::system_clock::now();
            m_autoDisableTime = now + std::chrono::minutes(m_currentProfile.autoDisableMinutes);
        }

        m_gameModeActive = true;
        m_activationReason = reason;
        m_status = GameModeStatus::Active;

        m_stats.totalSessions++;
        if (reason == ActivationReason::Manual || reason == ActivationReason::API) {
            m_stats.manualActivations++;
        } else {
            m_stats.autoActivations++;
        }

        lock.unlock();

        NotifyStateChange(true, reason);

        Utils::Logger::Info("Game mode activated (profile: {}, reason: {})",
            targetProfile, static_cast<int>(reason));
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Activate failed: {}", e.what());
        m_status = GameModeStatus::Error;
        return false;
    }
}

// Fix #10: Internal deactivation core that assumes m_mutex is held exclusively
void GameModeManagerImpl::DeactivateCore_Locked() {
    if (!m_gameModeActive) {
        return;
    }

    m_status = GameModeStatus::Transitioning;

    // End current session
    EndCurrentSession();

    // Restore normal mode
    RestoreNormalMode();

    // Track fullscreen deactivation for hysteresis (Fix #21)
    if (m_activationReason.load() == ActivationReason::FullscreenDetected) {
        m_lastFullscreenDeactivation = Clock::now();
    }

    m_gameModeActive = false;
    m_autoDisableTime.reset();
    m_status = GameModeStatus::Inactive;
}

// Fix #5: Deactivate no longer blocks the caller with a 30s sleep.
// Resume delay is handled in a separate detached thread.
void GameModeManagerImpl::Deactivate() {
    try {
        ActivationReason reason;
        uint32_t resumeDelay = 0;

        {
            std::unique_lock lock(m_mutex);

            if (!m_gameModeActive) {
                return;
            }

            reason = m_activationReason.load();
            resumeDelay = m_config.resumeDelaySeconds;

            DeactivateCore_Locked();
        }

        // Schedule deferred action execution via managed worker thread.
        // Resume worker is joined in Shutdown, so no UAF possible.
        ScheduleDeferredResume(resumeDelay);

        NotifyStateChange(false, reason);

        Utils::Logger::Info("Game mode deactivated");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Deactivate failed: {}", e.what());
    }
}

ProtectionLevel GameModeManagerImpl::GetProtectionLevel() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_gameModeActive ? m_currentProfile.protectionLevel : ProtectionLevel::Full;
}

void GameModeManagerImpl::OnGameStateChanged(bool isGaming) {
    if (isGaming) {
        if (!m_gameModeActive && m_config.autoDetectionEnabled) {
            Activate("", ActivationReason::GameDetected);
        }
    } else {
        if (m_gameModeActive && m_activationReason != ActivationReason::Manual) {
            Deactivate();
        }
    }
}

void GameModeManagerImpl::OnGameDetected(uint32_t pid, const std::wstring& processName) {
    try {
        GameDetectedCallback cbCopy;

        {
            std::unique_lock lock(m_mutex);

            if (m_gameModeActive) {
                return;  // Already active
            }

            if (!m_config.autoDetectionEnabled || !m_config.enabled) {
                return;
            }

            m_status = GameModeStatus::Transitioning;

            // Get default profile
            auto profileIt = m_profiles.find(m_config.defaultProfile);
            if (profileIt == m_profiles.end()) {
                Utils::Logger::Warn("GameModeManager: default profile '{}' not found, "
                    "cannot activate game mode for detected process", m_config.defaultProfile);
                m_status = GameModeStatus::Inactive;
                return;
            }

            m_currentProfile = profileIt->second;

            // Create session
            GameSession session;
            session.sessionId = GenerateSessionId();
            session.processId = pid;
            session.processName = processName;
            session.gameTitle = Utils::StringUtils::WStringToString(processName);
            session.startedTime = std::chrono::system_clock::now();
            session.reason = ActivationReason::GameDetected;

            m_currentSession = session;

            // Apply profile
            ApplyProfile(m_currentProfile);

            m_gameModeActive = true;
            m_activationReason = ActivationReason::GameDetected;
            m_status = GameModeStatus::Active;

            m_stats.totalSessions++;
            m_stats.autoActivations++;

            // Fix #9: Copy callback under lock before invoking outside
            cbCopy = m_gameDetectedCallback;
        }

        if (cbCopy) {
            try {
                cbCopy(pid, processName);
            } catch (const std::exception& ex) {
                Utils::Logger::Error("GameModeManager: game detected callback exception: {}", ex.what());
            } catch (...) {
                Utils::Logger::Error("GameModeManager: unknown game detected callback exception");
            }
        }

        NotifyStateChange(true, ActivationReason::GameDetected);

        Utils::Logger::Info("Game detected: {} (PID: {})",
            Utils::StringUtils::WStringToString(processName), pid);

    } catch (const std::exception& e) {
        Utils::Logger::Error("OnGameDetected failed: {}", e.what());
    }
}

// Fix #10: OnGameExited uses unique_lock and deactivates atomically to prevent TOCTOU
void GameModeManagerImpl::OnGameExited(uint32_t pid) {
    ActivationReason reason;
    uint32_t resumeDelay = 0;
    bool shouldDeactivate = false;

    {
        std::unique_lock lock(m_mutex);

        if (!m_currentSession.has_value()) {
            return;
        }

        if (m_currentSession->processId == pid) {
            reason = m_activationReason.load();
            resumeDelay = m_config.resumeDelaySeconds;
            DeactivateCore_Locked();
            shouldDeactivate = true;
        }
    }

    if (shouldDeactivate) {
        // Schedule via managed worker (no detach).
        ScheduleDeferredResume(resumeDelay);

        NotifyStateChange(false, reason);

        Utils::Logger::Info("Game exited (PID: {}), game mode deactivated", pid);
    }
}

// ============================================================================
// PROFILE MANAGEMENT
// ============================================================================

std::vector<GameModeProfile> GameModeManagerImpl::GetProfiles() const {
    std::shared_lock lock(m_mutex);

    std::vector<GameModeProfile> profiles;
    profiles.reserve(m_profiles.size());

    for (const auto& [_, profile] : m_profiles) {
        profiles.push_back(profile);
    }

    return profiles;
}

std::optional<GameModeProfile> GameModeManagerImpl::GetProfile(const std::string& name) const {
    std::shared_lock lock(m_mutex);

    auto it = m_profiles.find(name);
    if (it != m_profiles.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool GameModeManagerImpl::SaveProfile(const GameModeProfile& profile) {
    std::unique_lock lock(m_mutex);

    try {
        if (profile.name.empty()) {
            Utils::Logger::Error("Profile name cannot be empty");
            return false;
        }

        m_profiles[profile.name] = profile;

        Utils::Logger::Info("Profile saved: {}", profile.name);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SaveProfile failed: {}", e.what());
        return false;
    }
}

bool GameModeManagerImpl::DeleteProfile(const std::string& name) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = m_profiles.find(name);
        if (it == m_profiles.end()) {
            return false;
        }

        if (it->second.isDefault) {
            Utils::Logger::Error("Cannot delete default profile");
            return false;
        }

        m_profiles.erase(it);

        Utils::Logger::Info("Profile deleted: {}", name);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeleteProfile failed: {}", e.what());
        return false;
    }
}

bool GameModeManagerImpl::SetDefaultProfile(const std::string& name) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = m_profiles.find(name);
        if (it == m_profiles.end()) {
            Utils::Logger::Error("Profile not found: {}", name);
            return false;
        }

        // Clear old default
        for (auto& [_, profile] : m_profiles) {
            profile.isDefault = false;
        }

        // Set new default
        it->second.isDefault = true;
        m_config.defaultProfile = name;

        Utils::Logger::Info("Default profile set: {}", name);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetDefaultProfile failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// SCHEDULING
// ============================================================================

std::vector<GameModeSchedule> GameModeManagerImpl::GetSchedules() const {
    std::shared_lock lock(m_mutex);
    return m_schedules;
}

bool GameModeManagerImpl::SaveSchedule(const GameModeSchedule& schedule) {
    std::unique_lock lock(m_mutex);

    try {
        if (schedule.ruleId.empty()) {
            Utils::Logger::Error("Schedule rule ID cannot be empty");
            return false;
        }

        // Find and update, or add new
        auto it = std::find_if(m_schedules.begin(), m_schedules.end(),
            [&schedule](const GameModeSchedule& s) { return s.ruleId == schedule.ruleId; });

        if (it != m_schedules.end()) {
            *it = schedule;
        } else {
            m_schedules.push_back(schedule);
        }

        Utils::Logger::Info("Schedule saved: {}", schedule.name);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SaveSchedule failed: {}", e.what());
        return false;
    }
}

bool GameModeManagerImpl::DeleteSchedule(const std::string& ruleId) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = std::remove_if(m_schedules.begin(), m_schedules.end(),
            [&ruleId](const GameModeSchedule& s) { return s.ruleId == ruleId; });

        if (it != m_schedules.end()) {
            m_schedules.erase(it, m_schedules.end());
            Utils::Logger::Info("Schedule deleted: {}", ruleId);
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeleteSchedule failed: {}", e.what());
        return false;
    }
}

bool GameModeManagerImpl::IsScheduledNow() const {
    std::shared_lock lock(m_mutex);

    for (const auto& schedule : m_schedules) {
        if (schedule.IsActiveNow()) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// ACTION DEFERRAL
// ============================================================================

// Fix #9: Copy callback under lock, invoke outside lock
void GameModeManagerImpl::DeferAction(const DeferredAction& action) {
    ActionDeferredCallback cbCopy;

    {
        std::unique_lock lock(m_mutex);

        try {
            if (m_deferredActions.size() >= GameModeConstants::MAX_DEFERRED_ACTIONS) {
                Utils::Logger::Warn("Maximum deferred actions reached");
                return;
            }

            m_deferredActions.push_back(action);
            m_stats.actionsDeferred++;

            if (m_currentSession.has_value()) {
                m_currentSession->actionsDeferred++;
            }

            // Copy callback under lock
            cbCopy = m_actionDeferredCallback;

        } catch (const std::exception& e) {
            Utils::Logger::Error("DeferAction failed: {}", e.what());
            return;
        }
    }

    // Invoke callback OUTSIDE lock
    if (cbCopy) {
        try {
            cbCopy(action);
        } catch (const std::exception& ex) {
            Utils::Logger::Error("GameModeManager: action deferred callback exception: {}", ex.what());
        } catch (...) {
            Utils::Logger::Error("GameModeManager: unknown action deferred callback exception");
        }
    }

    Utils::Logger::Info("Action deferred: {}", action.description);
}

std::vector<DeferredAction> GameModeManagerImpl::GetDeferredActions() const {
    std::shared_lock lock(m_mutex);
    return m_deferredActions;
}

// Fix #4: Dispatch via registered callback instead of log-only stubs
void GameModeManagerImpl::ExecuteDeferredActions() {
    std::vector<DeferredAction> actions;
    ActionDispatcherCallback dispatcher;

    {
        std::unique_lock lock(m_mutex);
        actions = std::move(m_deferredActions);
        m_deferredActions.clear();
        dispatcher = m_actionDispatcher;
    }

    if (actions.empty()) {
        return;
    }

    // Sort by priority (higher first)
    std::sort(actions.begin(), actions.end(),
        [](const DeferredAction& a, const DeferredAction& b) {
            return a.priority > b.priority;
        });

    Utils::Logger::Info("Executing {} deferred actions", actions.size());

    for (const auto& action : actions) {
        try {
            if (dispatcher) {
                dispatcher(action.actionType, action.context);
                Utils::Logger::Info("Dispatched deferred action via dispatcher: {} (type: {})",
                    action.description, static_cast<int>(action.actionType));
            } else {
                Utils::Logger::Warn("No action dispatcher registered, logging deferred action: {} (type: {})",
                    action.description, static_cast<int>(action.actionType));
            }

            // Track statistics regardless of dispatch path
            if (action.actionType == DeferredActionType::Scan) {
                m_stats.scansPostponed++;
            } else if (action.actionType == DeferredActionType::Notification) {
                m_stats.notificationsSuppressed++;
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("Failed to execute deferred action '{}': {}",
                action.description, e.what());
        }
    }

    Utils::Logger::Info("Deferred actions executed: {} total", actions.size());
}

void GameModeManagerImpl::ClearDeferredActions() {
    std::unique_lock lock(m_mutex);
    m_deferredActions.clear();
    Utils::Logger::Info("Deferred actions cleared");
}

// ============================================================================
// SESSION HISTORY
// ============================================================================

std::optional<GameSession> GameModeManagerImpl::GetCurrentSession() const {
    std::shared_lock lock(m_mutex);
    return m_currentSession;
}

std::vector<GameSession> GameModeManagerImpl::GetSessionHistory(size_t limit) const {
    std::shared_lock lock(m_mutex);

    size_t count = std::min(m_sessionHistory.size(), limit);
    std::vector<GameSession> history;
    history.reserve(count);

    auto it = m_sessionHistory.begin();
    for (size_t i = 0; i < count && it != m_sessionHistory.end(); ++i, ++it) {
        history.push_back(*it);
    }

    return history;
}

// ============================================================================
// UTILITY CHECKS
// ============================================================================

bool GameModeManagerImpl::ShouldShowNotification(uint8_t severity) const {
    std::shared_lock lock(m_mutex);

    if (!m_gameModeActive) {
        return true;
    }

    switch (m_currentProfile.notificationPolicy) {
        case NotificationPolicy::All:
            return true;

        case NotificationPolicy::CriticalOnly:
            return severity >= 8;  // Critical severity threshold

        case NotificationPolicy::None:
            return false;

        default:
            return true;
    }
}

bool GameModeManagerImpl::ShouldDeferScan() const {
    std::shared_lock lock(m_mutex);
    return m_gameModeActive && m_currentProfile.postponeScans;
}

bool GameModeManagerImpl::ShouldDeferUpdate() const {
    std::shared_lock lock(m_mutex);
    return m_gameModeActive && m_currentProfile.postponeUpdates;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void GameModeManagerImpl::RegisterStateChangeCallback(StateChangeCallback callback) {
    std::unique_lock lock(m_mutex);
    m_stateChangeCallback = std::move(callback);
}

void GameModeManagerImpl::RegisterGameDetectedCallback(GameDetectedCallback callback) {
    std::unique_lock lock(m_mutex);
    m_gameDetectedCallback = std::move(callback);
}

void GameModeManagerImpl::RegisterActionDeferredCallback(ActionDeferredCallback callback) {
    std::unique_lock lock(m_mutex);
    m_actionDeferredCallback = std::move(callback);
}

void GameModeManagerImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_errorCallback = std::move(callback);
}

void GameModeManagerImpl::RegisterActionDispatcher(ActionDispatcherCallback dispatcher) {
    std::unique_lock lock(m_mutex);
    m_actionDispatcher = std::move(dispatcher);
}

void GameModeManagerImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_stateChangeCallback = nullptr;
    m_gameDetectedCallback = nullptr;
    m_actionDeferredCallback = nullptr;
    m_errorCallback = nullptr;
    m_actionDispatcher = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

// Fix #22: Statistics are individually atomic-consistent but the aggregate snapshot
// is approximate - each atomic is loaded independently, so the snapshot may reflect
// a mix of states if counters are being updated concurrently. This is acceptable
// for monitoring/telemetry purposes and avoids holding a lock across all loads.
// L1-FIX: Removed shared_lock — all stats fields are std::atomic, so acquiring the
// mutex adds contention on writers with no correctness benefit for readers.
GameModeStatistics GameModeManagerImpl::GetStatistics() const {
    GameModeStatistics snapshot;
    snapshot.totalSessions.store(m_stats.totalSessions.load(std::memory_order_relaxed),
                                 std::memory_order_relaxed);
    snapshot.totalDurationSeconds.store(m_stats.totalDurationSeconds.load(std::memory_order_relaxed),
                                        std::memory_order_relaxed);
    snapshot.autoActivations.store(m_stats.autoActivations.load(std::memory_order_relaxed),
                                   std::memory_order_relaxed);
    snapshot.manualActivations.store(m_stats.manualActivations.load(std::memory_order_relaxed),
                                     std::memory_order_relaxed);
    snapshot.threatsBlocked.store(m_stats.threatsBlocked.load(std::memory_order_relaxed),
                                  std::memory_order_relaxed);
    snapshot.actionsDeferred.store(m_stats.actionsDeferred.load(std::memory_order_relaxed),
                                   std::memory_order_relaxed);
    snapshot.scansPostponed.store(m_stats.scansPostponed.load(std::memory_order_relaxed),
                                  std::memory_order_relaxed);
    snapshot.notificationsSuppressed.store(m_stats.notificationsSuppressed.load(std::memory_order_relaxed),
                                           std::memory_order_relaxed);
    snapshot.startTime = m_stats.startTime;
    return snapshot;
}

void GameModeManagerImpl::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_stats.Reset();
    Utils::Logger::Info("Statistics reset");
}

bool GameModeManagerImpl::SelfTest() {
    Utils::Logger::Info("Running GameModeManager self-test...");

    // RAII guard ensures test artifacts are cleaned up on every exit path
    struct TestCleanup {
        GameModeManagerImpl* self;
        bool profileCreated = false;
        bool actionsDeferred = false;
        ~TestCleanup() {
            if (actionsDeferred) self->ClearDeferredActions();
            if (profileCreated) self->DeleteProfile("TestProfile");
        }
    } guard{this};

    try {
        // Test 1: Profile creation
        GameModeProfile testProfile;
        testProfile.name = "TestProfile";
        testProfile.description = "Test";
        testProfile.protectionLevel = ProtectionLevel::Balanced;

        if (!SaveProfile(testProfile)) {
            Utils::Logger::Error("Self-test failed: Profile creation");
            return false;
        }
        guard.profileCreated = true;
        Utils::Logger::Info("[PASS] Profile creation test passed");

        // Test 2: Schedule evaluation
        GameModeSchedule testSchedule;
        testSchedule.ruleId = "TEST-001";
        testSchedule.name = "Test Schedule";
        testSchedule.daysOfWeek = 0x7F;  // All days
        testSchedule.startMinutes = 0;
        testSchedule.endMinutes = 1440;  // Full day
        testSchedule.enabled = true;

        if (!testSchedule.IsActiveNow()) {
            Utils::Logger::Error("Self-test failed: Schedule evaluation");
            return false;
        }
        Utils::Logger::Info("[PASS] Schedule evaluation test passed");

        // Test 3: Deferred action
        DeferredAction testAction;
        testAction.actionId = GenerateActionId();
        testAction.actionType = DeferredActionType::Scan;
        testAction.description = "Test action";
        testAction.deferredTime = std::chrono::system_clock::now();
        testAction.priority = 5;

        DeferAction(testAction);
        guard.actionsDeferred = true;

        auto actions = GetDeferredActions();
        if (actions.empty()) {
            Utils::Logger::Error("Self-test failed: Deferred action");
            return false;
        }
        Utils::Logger::Info("[PASS] Deferred action test passed");

        // Test 4: Configuration validation
        GameModeConfiguration testConfig;
        testConfig.enabled = true;
        testConfig.autoDetectionEnabled = true;
        testConfig.detectionIntervalMs = 5000;
        testConfig.defaultProfile = "Balanced";

        if (!testConfig.IsValid()) {
            Utils::Logger::Error("Self-test failed: Configuration validation");
            return false;
        }
        Utils::Logger::Info("[PASS] Configuration validation test passed");

        Utils::Logger::Info("All GameModeManager self-tests passed!");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Fatal("Self-test failed with exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

// Fix #8: Snapshot config fields under shared_lock at the start of each detection loop iteration
// Fix #17: Don't use GetLastError() in catch block after a C++ exception
void GameModeManagerImpl::DetectionThreadFunc() {
    Utils::Logger::Info("Detection thread started");

    try {
        while (!m_stopDetection.load(std::memory_order_acquire)) {
            // Fix #8: Snapshot config fields under shared_lock
            bool autoDetect = false;
            bool fullscreenDetect = false;
            bool launcherDetect = false;
            bool vrDetect = false;
            uint32_t intervalMs = GameModeConstants::DEFAULT_DETECTION_INTERVAL_MS;
            bool gameModeActive = false;
            std::optional<SystemTimePoint> autoDisableSnapshot;

            {
                std::shared_lock lock(m_mutex);
                autoDetect = m_config.autoDetectionEnabled;
                fullscreenDetect = m_config.fullscreenDetectionEnabled;
                launcherDetect = m_config.launcherDetectionEnabled;
                vrDetect = m_config.vrDetectionEnabled;
                intervalMs = m_config.detectionIntervalMs;
                gameModeActive = m_gameModeActive.load();
                autoDisableSnapshot = m_autoDisableTime;
            }

            bool gameDetected = false;

            // Detect games
            if (autoDetect) {
                gameDetected |= DetectGames();
            }

            // Detect fullscreen apps
            if (fullscreenDetect) {
                gameDetected |= DetectFullscreenApps();
            }

            // Detect launchers
            if (launcherDetect) {
                gameDetected |= DetectLaunchers();
            }

            // Detect VR apps
            if (vrDetect) {
                gameDetected |= DetectVRApps();
            }

            // Detect streaming apps
            if (autoDetect) {
                gameDetected |= DetectStreamingApps();
            }

            // Check auto-disable timeout using snapshotted values
            if (gameModeActive && autoDisableSnapshot.has_value()) {
                if (std::chrono::system_clock::now() >= *autoDisableSnapshot) {
                    Utils::Logger::Info("Auto-disable timeout reached");
                    Deactivate();
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Detection thread exception: {}", e.what());
        // Fix #17: Pass -1 instead of stale GetLastError() inside a catch block
        NotifyError("Detection thread error", -1);
    }

    Utils::Logger::Info("Detection thread stopped");
}

// Fix #7: Restructured to avoid holding lock while calling Activate.
// Hold shared_lock only to find matching schedule and copy profileName,
// then release lock before calling Activate.
void GameModeManagerImpl::ScheduleCheckThreadFunc() {
    Utils::Logger::Info("Schedule check thread started");

    try {
        while (!m_stopSchedule.load(std::memory_order_acquire)) {
            // Phase 1: Under shared_lock, check if any schedule is active and
            // extract the profile name without invoking Activate under lock.
            std::string matchedProfileName;
            bool scheduledNow = false;
            bool enabled = false;

            {
                std::shared_lock lock(m_mutex);
                enabled = m_config.enabled;
                for (const auto& schedule : m_schedules) {
                    if (schedule.IsActiveNow()) {
                        scheduledNow = true;
                        matchedProfileName = schedule.profileName;
                        break;
                    }
                }
            }

            // Phase 2: Act on findings with NO lock held
            if (scheduledNow && !m_gameModeActive.load() && enabled) {
                Activate(matchedProfileName, ActivationReason::Scheduled);
            } else if (!scheduledNow && m_gameModeActive.load() &&
                       m_activationReason.load() == ActivationReason::Scheduled) {
                // Deactivate when schedule ends
                Deactivate();
            }

            std::this_thread::sleep_for(std::chrono::seconds(60));  // Check every minute
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Schedule thread exception: {}", e.what());
    }

    Utils::Logger::Info("Schedule check thread stopped");
}

// Managed resume worker. Waits on a condition_variable for either shutdown
// or a scheduled deadline. Guarantees no detached threads survive Shutdown().
void GameModeManagerImpl::ResumeWorkerThreadFunc() {
    Utils::Logger::Info("Resume worker thread started");

    try {
        std::unique_lock<std::mutex> lock(m_resumeMutex);
        while (!m_stopResume.load(std::memory_order_acquire)) {
            if (!m_pendingResumeDeadline.has_value()) {
                m_resumeCv.wait(lock, [this]() {
                    return m_stopResume.load(std::memory_order_acquire) ||
                           m_pendingResumeDeadline.has_value();
                });
                if (m_stopResume.load(std::memory_order_acquire)) {
                    break;
                }
            }

            if (!m_pendingResumeDeadline.has_value()) {
                continue;
            }

            const auto deadline = *m_pendingResumeDeadline;
            // wait_until returns true if predicate fires (stop requested),
            // false on timeout (deadline reached).
            const bool stopRequested = m_resumeCv.wait_until(lock, deadline,
                [this]() { return m_stopResume.load(std::memory_order_acquire); });

            if (stopRequested) {
                break;
            }

            // Deadline reached; clear it before running the action so a
            // newly scheduled resume during ExecuteDeferredActions() is
            // honored after we finish.
            m_pendingResumeDeadline.reset();
            lock.unlock();

            try {
                if (m_initialized.load(std::memory_order_acquire) &&
                    !m_stopResume.load(std::memory_order_acquire)) {
                    ExecuteDeferredActions();
                }
            } catch (const std::exception& e) {
                Utils::Logger::Error("Resume worker ExecuteDeferredActions failed: {}", e.what());
            }

            lock.lock();
        }
    } catch (const std::exception& e) {
        Utils::Logger::Error("Resume worker thread exception: {}", e.what());
    }

    Utils::Logger::Info("Resume worker thread stopped");
}

// Schedules a deferred resume N seconds from now. Coalesces with any
// existing earlier-pending deadline. Zero delay runs synchronously.
void GameModeManagerImpl::ScheduleDeferredResume(uint32_t delaySeconds) {
    if (delaySeconds == 0) {
        try {
            ExecuteDeferredActions();
        } catch (const std::exception& e) {
            Utils::Logger::Error("ExecuteDeferredActions (immediate) failed: {}", e.what());
        }
        return;
    }

    const auto deadline = Clock::now() + std::chrono::seconds(delaySeconds);
    {
        std::lock_guard<std::mutex> lock(m_resumeMutex);
        if (!m_pendingResumeDeadline.has_value() || deadline < *m_pendingResumeDeadline) {
            m_pendingResumeDeadline = deadline;
        }
    }
    m_resumeCv.notify_all();
}

// Fix #1: Real ApplyProfile implementation using PerformanceOptimizer and OverlayProtection
void GameModeManagerImpl::ApplyProfile(const GameModeProfile& profile) {
    Utils::Logger::Info("Applying profile: {}", profile.name);

    // Map GameMode ProtectionLevel to PerformanceOptimizer OptimizationProfile
    OptimizationProfile optProfile = OptimizationProfile::Normal;
    switch (profile.protectionLevel) {
        case ProtectionLevel::Balanced:
            optProfile = OptimizationProfile::Balanced;
            break;
        case ProtectionLevel::Performance:
            optProfile = OptimizationProfile::Performance;
            break;
        case ProtectionLevel::Full:
            optProfile = OptimizationProfile::Normal;
            break;
        case ProtectionLevel::Custom:
            optProfile = OptimizationProfile::Custom;
            break;
    }

    // Apply the performance optimization profile
    auto result = PerformanceOptimizer::Instance().ApplyProfile(optProfile);
    if (!result.success) {
        Utils::Logger::Warn("PerformanceOptimizer failed to apply profile: {}",
            result.errorMessage);
    } else {
        Utils::Logger::Info("PerformanceOptimizer applied profile (modified {} processes, "
                            "freed {} MB, estimated gain {:.1f}%)",
            result.processesModified, result.memoryFreedMB, result.estimatedGainPercent);
    }

    // Start overlay integrity monitoring if enabled in the profile
    if (profile.enableOverlayProtection) {
        OverlayProtection::Instance().StartIntegrityMonitoring();
        Utils::Logger::Info("Overlay integrity monitoring started");
    }

    Utils::Logger::Info("Protection level: {}",
        static_cast<int>(profile.protectionLevel));
    Utils::Logger::Info("Resource priority: {}",
        static_cast<int>(profile.resourcePriority));
    Utils::Logger::Info("Notification policy: {}",
        static_cast<int>(profile.notificationPolicy));
}

// Fix #2: Real RestoreNormalMode implementation
void GameModeManagerImpl::RestoreNormalMode() {
    Utils::Logger::Info("Restoring normal mode");

    // Restore system to normal performance profile
    auto result = PerformanceOptimizer::Instance().RestoreSystem();
    if (!result.success) {
        Utils::Logger::Warn("PerformanceOptimizer restore failed: {}",
            result.errorMessage);
    } else {
        Utils::Logger::Info("PerformanceOptimizer restored system (restored {} processes)",
            result.processesModified);
    }

    // Stop overlay integrity monitoring
    OverlayProtection::Instance().StopIntegrityMonitoring();
    Utils::Logger::Info("Overlay integrity monitoring stopped");
}

// Fix #3: DetectGames delegates to GameProcessDetector
bool GameModeManagerImpl::DetectGames() {
    try {
        if (!GameProcessDetector::Instance().IsAnyGameRunning()) {
            return false;
        }

        // A game is detected and we are not already in game mode
        if (m_gameModeActive.load(std::memory_order_acquire)) {
            return true;  // Already active, nothing more to do
        }

        // Get the detected games list and trigger OnGameDetected for the first one
        auto detectedGames = GameProcessDetector::Instance().GetDetectedGames();
        if (!detectedGames.empty()) {
            const auto& firstGame = detectedGames.front();
            OnGameDetected(firstGame.processId, firstGame.processName);
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("DetectGames exception: {}", e.what());
        return false;
    }
}

// Fix #12: Blocklist for non-game processes
// Fix #18: ScopedHandle RAII for CreateToolhelp32Snapshot
// Fix #21: Fullscreen hysteresis - require consecutive detections and cooldown
// C4: Read m_lastFullscreenDeactivation under shared_lock to avoid data race
bool GameModeManagerImpl::DetectFullscreenApps() {
    // C4: Acquire lock to read m_lastFullscreenDeactivation safely
    TimePoint lastDeactivation;
    {
        std::shared_lock lock(m_mutex);
        lastDeactivation = m_lastFullscreenDeactivation;
    }

    // Fix #21: Enforce cooldown after deactivation
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - lastDeactivation);
    if (elapsed.count() < FULLSCREEN_COOLDOWN_SECONDS &&
        lastDeactivation.time_since_epoch().count() > 0) {
        return false;
    }

    // Fix #18: ScopedHandle for process snapshot
    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return false;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot.Get(), &entry)) {
        return false;
    }

    bool detected = false;
    uint32_t detectedPid = 0;
    std::wstring detectedName;

    do {
        std::wstring processName = entry.szExeFile;

        // Fix #12: Skip blocklisted non-game processes
        if (IsBlocklistedProcess(processName)) {
            continue;
        }

        // Cross-reference with GameProcessDetector if available
        // Only consider processes that the detector knows about or
        // that are genuinely fullscreen and not in the blocklist
        if (IsProcessFullscreen(entry.th32ProcessID)) {
            // Additional validation: check if GameProcessDetector recognizes this
            bool knownGame = false;
            try {
                knownGame = GameProcessDetector::Instance().IsGameProcess(entry.th32ProcessID);
            } catch (...) {
                // If detector unavailable, proceed with fullscreen-only heuristic
            }

            // If it passes the blocklist, it is either a known game or at
            // least not a known non-game - allow proceeding
            detectedPid = entry.th32ProcessID;
            detectedName = processName;
            detected = true;
            break;
        }

    } while (Process32NextW(snapshot.Get(), &entry));

    if (!detected) {
        // Reset consecutive count when no fullscreen app found
        m_consecutiveFullscreenCount.store(0, std::memory_order_relaxed);
        return false;
    }

    // Fix #21: Hysteresis - require consecutive detections before activating
    uint32_t count = m_consecutiveFullscreenCount.fetch_add(1, std::memory_order_relaxed) + 1;
    if (count < FULLSCREEN_CONSECUTIVE_THRESHOLD) {
        return false;  // Not enough consecutive detections yet
    }

    // Threshold met - activate
    m_consecutiveFullscreenCount.store(0, std::memory_order_relaxed);
    OnGameDetected(detectedPid, detectedName);
    return true;
}

// Fix #13: Case-insensitive launcher match using _wcsicmp
// Fix #18: ScopedHandle RAII
// H1: Launcher detection sets flag only — does not activate game mode
bool GameModeManagerImpl::DetectLaunchers() {
    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return false;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot.Get(), &entry)) {
        return false;
    }

    bool detected = false;

    do {
        std::wstring processName = entry.szExeFile;

        for (const auto& launcher : KNOWN_LAUNCHERS) {
            // Fix #13: Case-insensitive comparison
            if (_wcsicmp(processName.c_str(), launcher.c_str()) == 0) {
                Utils::Logger::Info("Launcher detected: {} (PID: {}), flagging for sensitivity increase",
                    Utils::StringUtils::WStringToString(processName), entry.th32ProcessID);
                m_launcherDetected.store(true, std::memory_order_release);
                detected = true;
                break;
            }
        }

        if (detected) break;

    } while (Process32NextW(snapshot.Get(), &entry));

    if (!detected) {
        m_launcherDetected.store(false, std::memory_order_release);
    }

    return false;  // Launcher alone does not activate game mode
}

// Fix #18: ScopedHandle RAII + case-insensitive match for consistency
bool GameModeManagerImpl::DetectVRApps() {
    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return false;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot.Get(), &entry)) {
        return false;
    }

    bool detected = false;

    do {
        std::wstring processName = entry.szExeFile;

        for (const auto& vrApp : VR_APPLICATIONS) {
            if (_wcsicmp(processName.c_str(), vrApp.c_str()) == 0) {
                OnGameDetected(entry.th32ProcessID, processName);
                detected = true;
                break;
            }
        }

        if (detected) break;

    } while (Process32NextW(snapshot.Get(), &entry));

    return detected;
}

// H2: Detect streaming/recording applications and activate game mode
bool GameModeManagerImpl::DetectStreamingApps() {
    if (m_gameModeActive.load(std::memory_order_acquire)) {
        return false;  // Already active
    }

    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return false;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot.Get(), &entry)) {
        return false;
    }

    bool detected = false;

    do {
        std::wstring processName = entry.szExeFile;

        for (const auto& streamApp : STREAMING_APPS) {
            if (_wcsicmp(processName.c_str(), streamApp.c_str()) == 0) {
                Utils::Logger::Info("Streaming app detected: {} (PID: {})",
                    Utils::StringUtils::WStringToString(processName), entry.th32ProcessID);
                Activate("", ActivationReason::StreamingActive);
                detected = true;
                break;
            }
        }

        if (detected) break;

    } while (Process32NextW(snapshot.Get(), &entry));

    return detected;
}

// Fix #9: Copy callback under lock, invoke outside lock
void GameModeManagerImpl::NotifyStateChange(bool active, ActivationReason reason) {
    StateChangeCallback cbCopy;
    {
        std::shared_lock lock(m_mutex);
        cbCopy = m_stateChangeCallback;
    }

    if (cbCopy) {
        try {
            cbCopy(active, reason);
        } catch (const std::exception& e) {
            Utils::Logger::Error("State change callback exception: {}", e.what());
        }
    }
}

// Fix #9: Copy callback under lock, invoke outside lock
void GameModeManagerImpl::NotifyError(const std::string& message, int code) {
    ErrorCallback cbCopy;
    {
        std::shared_lock lock(m_mutex);
        cbCopy = m_errorCallback;
    }

    if (cbCopy) {
        try {
            cbCopy(message, code);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Error callback exception: {}", e.what());
        }
    }
}

void GameModeManagerImpl::CreateDefaultProfiles() {
    // Balanced profile
    {
        GameModeProfile profile;
        profile.name = "Balanced";
        profile.description = "Balanced protection and performance";
        profile.protectionLevel = ProtectionLevel::Balanced;
        profile.resourcePriority = ResourcePriority::Low;
        profile.notificationPolicy = NotificationPolicy::CriticalOnly;
        profile.postponeScans = true;
        profile.postponeUpdates = true;
        profile.reduceRealtimeScan = false;
        profile.criticalAlertsOnly = true;
        profile.enableOverlayProtection = true;
        profile.autoDisableMinutes = 0;
        profile.isDefault = true;

        m_profiles[profile.name] = profile;
    }

    // Performance profile
    {
        GameModeProfile profile;
        profile.name = "Performance";
        profile.description = "Maximum performance, minimal scanning";
        profile.protectionLevel = ProtectionLevel::Performance;
        profile.resourcePriority = ResourcePriority::Idle;
        profile.notificationPolicy = NotificationPolicy::None;
        profile.postponeScans = true;
        profile.postponeUpdates = true;
        profile.reduceRealtimeScan = true;
        profile.criticalAlertsOnly = false;
        profile.enableOverlayProtection = false;
        profile.autoDisableMinutes = 0;
        profile.isDefault = false;

        m_profiles[profile.name] = profile;
    }

    // Full Protection profile
    {
        GameModeProfile profile;
        profile.name = "FullProtection";
        profile.description = "Full protection, no compromises";
        profile.protectionLevel = ProtectionLevel::Full;
        profile.resourcePriority = ResourcePriority::Normal;
        profile.notificationPolicy = NotificationPolicy::All;
        profile.postponeScans = false;
        profile.postponeUpdates = false;
        profile.reduceRealtimeScan = false;
        profile.criticalAlertsOnly = false;
        profile.enableOverlayProtection = true;
        profile.autoDisableMinutes = 0;
        profile.isDefault = false;

        m_profiles[profile.name] = profile;
    }

    Utils::Logger::Info("Created {} default profiles", m_profiles.size());
}

// Fix #15: Session history uses std::deque with push_front for O(1) insert at front
void GameModeManagerImpl::EndCurrentSession() {
    if (!m_currentSession.has_value()) {
        return;
    }

    auto& session = *m_currentSession;
    session.endedTime = std::chrono::system_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        *session.endedTime - session.startedTime);
    session.durationSeconds = duration.count();

    m_stats.totalDurationSeconds += session.durationSeconds;

    // Fix #15: O(1) push_front with deque instead of O(n) vector::insert
    m_sessionHistory.push_front(session);

    // Limit history size
    while (m_sessionHistory.size() > 1000) {
        m_sessionHistory.pop_back();
    }

    m_currentSession.reset();

    Utils::Logger::Info("Session ended (duration: {}s)", session.durationSeconds);
}

// ============================================================================
// PUBLIC API IMPLEMENTATION (SINGLETON)
// ============================================================================

GameModeManager& GameModeManager::Instance() noexcept {
    static GameModeManager instance;
    return instance;
}

bool GameModeManager::HasInstance() noexcept {
    return s_instanceCreated.load();
}

GameModeManager::GameModeManager()
    : m_impl(std::make_unique<GameModeManagerImpl>()) {
    s_instanceCreated = true;
}

GameModeManager::~GameModeManager() {
    s_instanceCreated = false;
}

// Forward all public methods to implementation

bool GameModeManager::Initialize(const GameModeConfiguration& config) {
    return m_impl->Initialize(config);
}

void GameModeManager::Shutdown() {
    m_impl->Shutdown();
}

bool GameModeManager::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

GameModeStatus GameModeManager::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool GameModeManager::UpdateConfiguration(const GameModeConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

GameModeConfiguration GameModeManager::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void GameModeManager::SetEnabled(bool enabled) {
    m_impl->SetEnabled(enabled);
}

// Fix #11: Forward reason parameter
bool GameModeManager::Activate(const std::string& profileName,
                                ActivationReason reason) {
    m_manualOverride = true;
    return m_impl->Activate(profileName, reason);
}

void GameModeManager::Deactivate() {
    m_manualOverride = false;
    m_impl->Deactivate();
}

bool GameModeManager::IsActive() const noexcept {
    return m_impl->IsActive();
}

ActivationReason GameModeManager::GetActivationReason() const noexcept {
    return m_impl->GetActivationReason();
}

ProtectionLevel GameModeManager::GetProtectionLevel() const noexcept {
    return m_impl->GetProtectionLevel();
}

void GameModeManager::OnGameStateChanged(bool isGaming) {
    if (!m_manualOverride) {
        m_autoDetected = isGaming;
        m_impl->OnGameStateChanged(isGaming);
    }
}

void GameModeManager::OnGameDetected(uint32_t pid, const std::wstring& processName) {
    if (!m_manualOverride) {
        m_autoDetected = true;
        m_impl->OnGameDetected(pid, processName);
    }
}

void GameModeManager::OnGameExited(uint32_t pid) {
    if (!m_manualOverride && m_autoDetected) {
        m_impl->OnGameExited(pid);
    }
}

std::vector<GameModeProfile> GameModeManager::GetProfiles() const {
    return m_impl->GetProfiles();
}

std::optional<GameModeProfile> GameModeManager::GetProfile(const std::string& name) const {
    return m_impl->GetProfile(name);
}

bool GameModeManager::SaveProfile(const GameModeProfile& profile) {
    return m_impl->SaveProfile(profile);
}

bool GameModeManager::DeleteProfile(const std::string& name) {
    return m_impl->DeleteProfile(name);
}

bool GameModeManager::SetDefaultProfile(const std::string& name) {
    return m_impl->SetDefaultProfile(name);
}

std::vector<GameModeSchedule> GameModeManager::GetSchedules() const {
    return m_impl->GetSchedules();
}

bool GameModeManager::SaveSchedule(const GameModeSchedule& schedule) {
    return m_impl->SaveSchedule(schedule);
}

bool GameModeManager::DeleteSchedule(const std::string& ruleId) {
    return m_impl->DeleteSchedule(ruleId);
}

bool GameModeManager::IsScheduledNow() const {
    return m_impl->IsScheduledNow();
}

void GameModeManager::DeferAction(const DeferredAction& action) {
    m_impl->DeferAction(action);
}

std::vector<DeferredAction> GameModeManager::GetDeferredActions() const {
    return m_impl->GetDeferredActions();
}

void GameModeManager::ExecuteDeferredActions() {
    m_impl->ExecuteDeferredActions();
}

void GameModeManager::ClearDeferredActions() {
    m_impl->ClearDeferredActions();
}

std::optional<GameSession> GameModeManager::GetCurrentSession() const {
    return m_impl->GetCurrentSession();
}

std::vector<GameSession> GameModeManager::GetSessionHistory(size_t limit) const {
    return m_impl->GetSessionHistory(limit);
}

bool GameModeManager::ShouldShowNotification(uint8_t severity) const {
    return m_impl->ShouldShowNotification(severity);
}

bool GameModeManager::ShouldDeferScan() const {
    return m_impl->ShouldDeferScan();
}

bool GameModeManager::ShouldDeferUpdate() const {
    return m_impl->ShouldDeferUpdate();
}

void GameModeManager::RegisterStateChangeCallback(StateChangeCallback callback) {
    m_impl->RegisterStateChangeCallback(std::move(callback));
}

void GameModeManager::RegisterGameDetectedCallback(GameDetectedCallback callback) {
    m_impl->RegisterGameDetectedCallback(std::move(callback));
}

void GameModeManager::RegisterActionDeferredCallback(ActionDeferredCallback callback) {
    m_impl->RegisterActionDeferredCallback(std::move(callback));
}

void GameModeManager::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void GameModeManager::RegisterActionDispatcher(ActionDispatcherCallback dispatcher) {
    m_impl->RegisterActionDispatcher(std::move(dispatcher));
}

void GameModeManager::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

GameModeStatistics GameModeManager::GetStatistics() const {
    return m_impl->GetStatistics();
}

void GameModeManager::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool GameModeManager::SelfTest() {
    return m_impl->SelfTest();
}

// Fix #19: Removed noexcept. Using snprintf for safe formatting without
// exception-throwing ostringstream.
std::string GameModeManager::GetVersionString() {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
        GameModeConstants::VERSION_MAJOR,
        GameModeConstants::VERSION_MINOR,
        GameModeConstants::VERSION_PATCH);
    return std::string(buf);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetActivationReasonName(ActivationReason reason) noexcept {
    switch (reason) {
        case ActivationReason::Manual: return "Manual";
        case ActivationReason::GameDetected: return "GameDetected";
        case ActivationReason::FullscreenDetected: return "FullscreenDetected";
        case ActivationReason::LauncherActive: return "LauncherActive";
        case ActivationReason::VRActive: return "VRActive";
        case ActivationReason::StreamingActive: return "StreamingActive";
        case ActivationReason::Scheduled: return "Scheduled";
        case ActivationReason::API: return "API";
        default: return "Unknown";
    }
}

std::string_view GetProtectionLevelName(ProtectionLevel level) noexcept {
    switch (level) {
        case ProtectionLevel::Full: return "Full";
        case ProtectionLevel::Balanced: return "Balanced";
        case ProtectionLevel::Performance: return "Performance";
        case ProtectionLevel::Custom: return "Custom";
        default: return "Unknown";
    }
}

std::string_view GetNotificationPolicyName(NotificationPolicy policy) noexcept {
    switch (policy) {
        case NotificationPolicy::All: return "All";
        case NotificationPolicy::CriticalOnly: return "CriticalOnly";
        case NotificationPolicy::None: return "None";
        default: return "Unknown";
    }
}

std::string_view GetDeferredActionTypeName(DeferredActionType type) noexcept {
    switch (type) {
        case DeferredActionType::Scan: return "Scan";
        case DeferredActionType::Update: return "Update";
        case DeferredActionType::Cleanup: return "Cleanup";
        case DeferredActionType::Notification: return "Notification";
        case DeferredActionType::Maintenance: return "Maintenance";
        default: return "Unknown";
    }
}

std::string_view GetStatusName(GameModeStatus status) noexcept {
    switch (status) {
        case GameModeStatus::Uninitialized: return "Uninitialized";
        case GameModeStatus::Initializing: return "Initializing";
        case GameModeStatus::Inactive: return "Inactive";
        case GameModeStatus::Active: return "Active";
        case GameModeStatus::Transitioning: return "Transitioning";
        case GameModeStatus::Stopping: return "Stopping";
        case GameModeStatus::Error: return "Error";
        default: return "Unknown";
    }
}

}  // namespace GameMode
}  // namespace ShadowStrike
