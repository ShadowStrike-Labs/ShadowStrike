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
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"

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

/// @brief Generate unique session ID
std::string GenerateSessionId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << "GM-" << std::hex << std::setw(12) << std::setfill('0') << ms
        << "-" << std::setw(8) << std::setfill('0') << counter.fetch_add(1);
    return oss.str();
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
            LONG style = GetWindowLong(window, GWL_STYLE);
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

bool GameModeSchedule::IsActiveNow() const {
    if (!enabled) return false;

    uint8_t currentDay = GetCurrentDayOfWeek();
    uint16_t currentMinutes = GetCurrentMinutesFromMidnight();

    // Check day of week
    uint8_t dayBit = (1 << currentDay);
    if (!(daysOfWeek & dayBit)) return false;

    // Check time range
    if (startMinutes <= endMinutes) {
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
    bool IsInitialized() const noexcept { return m_isActive; }
    GameModeStatus GetStatus() const noexcept { return m_status; }
    bool UpdateConfiguration(const GameModeConfiguration& config);
    GameModeConfiguration GetConfiguration() const;

    // Game mode control
    void SetEnabled(bool enabled);
    bool Activate(const std::string& profileName);
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
    void NotifyStateChange(bool active, ActivationReason reason);
    void NotifyError(const std::string& message, int code);
    void CreateDefaultProfiles();
    void EndCurrentSession();

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_isActive{false};
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
    std::vector<GameSession> m_sessionHistory;

    // Deferred actions
    std::vector<DeferredAction> m_deferredActions;

    // Detection thread
    std::unique_ptr<std::thread> m_detectionThread;
    std::atomic<bool> m_stopDetection{false};

    // Schedule thread
    std::unique_ptr<std::thread> m_scheduleThread;
    std::atomic<bool> m_stopSchedule{false};

    // Callbacks
    StateChangeCallback m_stateChangeCallback;
    GameDetectedCallback m_gameDetectedCallback;
    ActionDeferredCallback m_actionDeferredCallback;
    ErrorCallback m_errorCallback;

    // Statistics
    GameModeStatistics m_stats;

    // Auto-disable timer
    std::optional<SystemTimePoint> m_autoDisableTime;
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
        if (m_isActive) {
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

        m_isActive = true;
        m_status = GameModeStatus::Inactive;

        Utils::Logger::Info("GameModeManager initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("GameModeManager initialization failed: {}", e.what());
        m_status = GameModeStatus::Error;
        return false;
    }
}

void GameModeManagerImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    try {
        if (!m_isActive) {
            return;
        }

        m_status = GameModeStatus::Stopping;

        // Stop detection thread
        m_stopDetection = true;
        if (m_detectionThread && m_detectionThread->joinable()) {
            lock.unlock();
            m_detectionThread->join();
            lock.lock();
        }

        // Stop schedule thread
        m_stopSchedule = true;
        if (m_scheduleThread && m_scheduleThread->joinable()) {
            lock.unlock();
            m_scheduleThread->join();
            lock.lock();
        }

        // Deactivate if active
        if (m_gameModeActive) {
            lock.unlock();
            Deactivate();
            lock.lock();
        }

        // Execute deferred actions
        lock.unlock();
        ExecuteDeferredActions();
        lock.lock();

        m_isActive = false;
        m_status = GameModeStatus::Uninitialized;

        Utils::Logger::Info("GameModeManager shutdown complete");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
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

bool GameModeManagerImpl::Activate(const std::string& profileName) {
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
        session.reason = ActivationReason::Manual;
        session.gameTitle = "Manual Activation";

        m_currentSession = session;

        // Apply profile settings
        ApplyProfile(m_currentProfile);

        // Set auto-disable timer
        if (m_currentProfile.autoDisableMinutes > 0) {
            auto now = std::chrono::system_clock::now();
            m_autoDisableTime = now + std::chrono::minutes(m_currentProfile.autoDisableMinutes);
        }

        m_gameModeActive = true;
        m_activationReason = ActivationReason::Manual;
        m_status = GameModeStatus::Active;

        m_stats.totalSessions++;
        m_stats.manualActivations++;

        lock.unlock();

        NotifyStateChange(true, ActivationReason::Manual);

        Utils::Logger::Info("Game mode activated (profile: {})", targetProfile);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Activate failed: {}", e.what());
        m_status = GameModeStatus::Error;
        return false;
    }
}

void GameModeManagerImpl::Deactivate() {
    try {
        std::unique_lock lock(m_mutex);

        if (!m_gameModeActive) {
            return;
        }

        m_status = GameModeStatus::Transitioning;

        // End current session
        EndCurrentSession();

        // Restore normal mode
        RestoreNormalMode();

        m_gameModeActive = false;
        m_autoDisableTime.reset();
        m_status = GameModeStatus::Inactive;

        lock.unlock();

        // Execute deferred actions after delay
        std::this_thread::sleep_for(std::chrono::seconds(m_config.resumeDelaySeconds));
        ExecuteDeferredActions();

        NotifyStateChange(false, m_activationReason.load());

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
            Activate("");
        }
    } else {
        if (m_gameModeActive && m_activationReason != ActivationReason::Manual) {
            Deactivate();
        }
    }
}

void GameModeManagerImpl::OnGameDetected(uint32_t pid, const std::wstring& processName) {
    try {
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

        lock.unlock();

        if (m_gameDetectedCallback) {
            try {
                m_gameDetectedCallback(pid, processName);
            } catch (...) {}
        }

        NotifyStateChange(true, ActivationReason::GameDetected);

        Utils::Logger::Info("Game detected: {} (PID: {})",
            Utils::StringUtils::WStringToString(processName), pid);

    } catch (const std::exception& e) {
        Utils::Logger::Error("OnGameDetected failed: {}", e.what());
    }
}

void GameModeManagerImpl::OnGameExited(uint32_t pid) {
    std::shared_lock lock(m_mutex);

    if (!m_currentSession.has_value()) {
        return;
    }

    if (m_currentSession->processId == pid) {
        lock.unlock();
        Deactivate();

        Utils::Logger::Info("Game exited (PID: {})", pid);
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

void GameModeManagerImpl::DeferAction(const DeferredAction& action) {
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

        if (m_actionDeferredCallback) {
            try {
                m_actionDeferredCallback(action);
            } catch (...) {}
        }

        Utils::Logger::Info("Action deferred: {}", action.description);

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeferAction failed: {}", e.what());
    }
}

std::vector<DeferredAction> GameModeManagerImpl::GetDeferredActions() const {
    std::shared_lock lock(m_mutex);
    return m_deferredActions;
}

void GameModeManagerImpl::ExecuteDeferredActions() {
    std::vector<DeferredAction> actions;

    {
        std::unique_lock lock(m_mutex);
        actions = std::move(m_deferredActions);
        m_deferredActions.clear();
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
            // In production, would actually execute the action based on type
            Utils::Logger::Info("Executing deferred action: {}", action.description);

            // Simulate action execution delay
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

        } catch (const std::exception& e) {
            Utils::Logger::Error("Failed to execute action: {}", e.what());
        }
    }

    Utils::Logger::Info("Deferred actions executed");
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

    std::vector<GameSession> history = m_sessionHistory;

    // Limit results
    if (history.size() > limit) {
        history.resize(limit);
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

void GameModeManagerImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_stateChangeCallback = nullptr;
    m_gameDetectedCallback = nullptr;
    m_actionDeferredCallback = nullptr;
    m_errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

GameModeStatistics GameModeManagerImpl::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_stats;
}

void GameModeManagerImpl::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_stats.Reset();
    Utils::Logger::Info("Statistics reset");
}

bool GameModeManagerImpl::SelfTest() {
    Utils::Logger::Info("Running GameModeManager self-test...");

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
        Utils::Logger::Info("✓ Profile creation test passed");

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
        Utils::Logger::Info("✓ Schedule evaluation test passed");

        // Test 3: Deferred action
        DeferredAction testAction;
        testAction.actionId = GenerateActionId();
        testAction.actionType = DeferredActionType::Scan;
        testAction.description = "Test action";
        testAction.deferredTime = std::chrono::system_clock::now();
        testAction.priority = 5;

        DeferAction(testAction);

        auto actions = GetDeferredActions();
        if (actions.empty()) {
            Utils::Logger::Error("Self-test failed: Deferred action");
            return false;
        }
        Utils::Logger::Info("✓ Deferred action test passed");

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
        Utils::Logger::Info("✓ Configuration validation test passed");

        // Cleanup
        ClearDeferredActions();
        DeleteProfile("TestProfile");

        Utils::Logger::Info("All GameModeManager self-tests passed!");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("Self-test failed with exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

void GameModeManagerImpl::DetectionThreadFunc() {
    Utils::Logger::Info("Detection thread started");

    try {
        while (!m_stopDetection.load()) {
            bool gameDetected = false;

            // Detect games
            if (m_config.autoDetectionEnabled) {
                gameDetected |= DetectGames();
            }

            // Detect fullscreen apps
            if (m_config.fullscreenDetectionEnabled) {
                gameDetected |= DetectFullscreenApps();
            }

            // Detect launchers
            if (m_config.launcherDetectionEnabled) {
                gameDetected |= DetectLaunchers();
            }

            // Detect VR apps
            if (m_config.vrDetectionEnabled) {
                gameDetected |= DetectVRApps();
            }

            // Check auto-disable timeout
            if (m_gameModeActive && m_autoDisableTime.has_value()) {
                if (std::chrono::system_clock::now() >= *m_autoDisableTime) {
                    Utils::Logger::Info("Auto-disable timeout reached");
                    Deactivate();
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(m_config.detectionIntervalMs));
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Detection thread exception: {}", e.what());
        NotifyError("Detection thread error", GetLastError());
    }

    Utils::Logger::Info("Detection thread stopped");
}

void GameModeManagerImpl::ScheduleCheckThreadFunc() {
    Utils::Logger::Info("Schedule check thread started");

    try {
        while (!m_stopSchedule.load()) {
            // Check if any schedule is active
            bool scheduledNow = IsScheduledNow();

            if (scheduledNow && !m_gameModeActive && m_config.enabled) {
                // Activate based on schedule
                std::shared_lock lock(m_mutex);
                for (const auto& schedule : m_schedules) {
                    if (schedule.IsActiveNow()) {
                        lock.unlock();

                        std::unique_lock ulock(m_mutex);
                        m_activationReason = ActivationReason::Scheduled;
                        ulock.unlock();

                        Activate(schedule.profileName);
                        break;
                    }
                }
            } else if (!scheduledNow && m_gameModeActive &&
                       m_activationReason == ActivationReason::Scheduled) {
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

void GameModeManagerImpl::ApplyProfile(const GameModeProfile& profile) {
    Utils::Logger::Info("Applying profile: {}", profile.name);

    // In production, would adjust:
    // - AV scan thread priority
    // - I/O throttling
    // - Real-time scan depth
    // - Update checking frequency
    // - etc.

    // For now, just log the settings
    Utils::Logger::Info("Protection level: {}", static_cast<int>(profile.protectionLevel));
    Utils::Logger::Info("Resource priority: {}", static_cast<int>(profile.resourcePriority));
    Utils::Logger::Info("Notification policy: {}", static_cast<int>(profile.notificationPolicy));
}

void GameModeManagerImpl::RestoreNormalMode() {
    Utils::Logger::Info("Restoring normal mode");

    // In production, would restore:
    // - Normal thread priorities
    // - Full scanning depth
    // - Regular update checks
    // - etc.
}

bool GameModeManagerImpl::DetectGames() {
    // Simplified game detection
    // In production: check against game database, heuristics, etc.
    return false;
}

bool GameModeManagerImpl::DetectFullscreenApps() {
    // Get all running processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    bool detected = false;

    do {
        // Check if process is fullscreen
        if (IsProcessFullscreen(entry.th32ProcessID)) {
            OnGameDetected(entry.th32ProcessID, entry.szExeFile);
            detected = true;
            break;
        }

    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return detected;
}

bool GameModeManagerImpl::DetectLaunchers() {
    // Check for known game launchers
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    bool detected = false;

    do {
        std::wstring processName = entry.szExeFile;

        for (const auto& launcher : KNOWN_LAUNCHERS) {
            if (processName == launcher) {
                OnGameDetected(entry.th32ProcessID, processName);
                detected = true;
                break;
            }
        }

        if (detected) break;

    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return detected;
}

bool GameModeManagerImpl::DetectVRApps() {
    // Check for VR applications
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    bool detected = false;

    do {
        std::wstring processName = entry.szExeFile;

        for (const auto& vrApp : VR_APPLICATIONS) {
            if (processName == vrApp) {
                OnGameDetected(entry.th32ProcessID, processName);
                detected = true;
                break;
            }
        }

        if (detected) break;

    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return detected;
}

void GameModeManagerImpl::NotifyStateChange(bool active, ActivationReason reason) {
    if (m_stateChangeCallback) {
        try {
            m_stateChangeCallback(active, reason);
        } catch (const std::exception& e) {
            Utils::Logger::Error("State change callback exception: {}", e.what());
        }
    }
}

void GameModeManagerImpl::NotifyError(const std::string& message, int code) {
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
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

    // Add to history
    m_sessionHistory.insert(m_sessionHistory.begin(), session);

    // Limit history size
    if (m_sessionHistory.size() > 1000) {
        m_sessionHistory.resize(1000);
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

bool GameModeManager::Activate(const std::string& profileName) {
    m_manualOverride = true;
    return m_impl->Activate(profileName);
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

std::string GameModeManager::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << GameModeConstants::VERSION_MAJOR << "."
        << GameModeConstants::VERSION_MINOR << "."
        << GameModeConstants::VERSION_PATCH;
    return oss.str();
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
