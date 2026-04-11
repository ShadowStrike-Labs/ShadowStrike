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
#include "pch.h"
#include "ProfileManager.hpp"
#include "../Utils/JSONUtils.hpp"

#include <sstream>
#include <algorithm>
#include <format>
#include <ctime>
#include <intrin.h>
#include <DsRole.h>
#pragma comment(lib, "netapi32.lib")

namespace ShadowStrike {
namespace Config {

using Json = Utils::JSON::Json;

// ============================================================================
// UTF-8 CONVERSION UTILITIES
// ============================================================================

static std::string WideToUtf8(std::wstring_view wide) noexcept {
    if (wide.empty()) return {};
    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string result(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        result.data(), needed, nullptr, nullptr);
    return result;
}

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* kLogCategory = L"ProfileMgr";

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class ProfileManagerImpl {
public:
    ProfileManagerConfiguration m_config;
    ProfileStatus m_status{ ProfileStatus::Uninitialized };

    std::map<SystemProfile, ProfileDefinition> m_builtInProfiles;
    std::map<std::string, ProfileDefinition> m_customProfiles;

    std::vector<ProfileScheduleEntry> m_scheduleEntries;
    uint64_t m_nextScheduleId{ 1 };

    std::vector<ApplicationTriggerRule> m_applicationTriggers;
    uint64_t m_nextTriggerId{ 1 };

    std::vector<ProfileSwitchEvent> m_switchHistory;
    std::unordered_map<uint64_t, ProfileSwitchCallback> m_switchCallbacks;
    ErrorCallback m_errorCallback;
    uint64_t m_nextCallbackId{ 1 };

    ProfileStatistics m_stats;

    std::atomic<bool> m_emergencyMode{ false };
    std::atomic<bool> m_shutdownRequested{ false };

    std::optional<ResourceLimits> m_resourceOverride;

    TimePoint m_lastSwitchTime;
    TimePoint m_profileStartTime;

    // Profile active before emergency mode was engaged
    SystemProfile m_preEmergencyProfile{ SystemProfile::Standard };

    // Tracks which custom profile is active when m_currentProfile == Custom
    std::string m_activeCustomProfileName;

    void PopulateBuiltInProfiles();
};

// ============================================================================
// BUILT-IN PROFILE DEFAULTS
// ============================================================================

void ProfileManagerImpl::PopulateBuiltInProfiles()
{
    auto now = std::chrono::system_clock::now();

    // --- Standard ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::Standard;
        def.description = "Balanced settings for general workstation use";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 50;
        def.resources.maxMemoryMb = 512;
        def.resources.ioPriority = 2;
        def.resources.maxConcurrentScans = 2;
        def.resources.backgroundMode = false;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = true;
        def.scan.scanArchives = true;
        def.scan.maxArchiveDepth = 5;
        def.scan.scanNetworkFiles = false;
        def.scan.heuristicLevel = 2;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = true;
        def.notifications.showScanProgress = true;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = true;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::Standard] = std::move(def);
    }

    // --- Server ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::Server;
        def.description = "Server-optimized profile for high availability workloads";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 25;
        def.resources.maxMemoryMb = 256;
        def.resources.ioPriority = 1;
        def.resources.maxConcurrentScans = 1;
        def.resources.backgroundMode = true;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = true;
        def.scan.scanArchives = true;
        def.scan.maxArchiveDepth = 5;
        def.scan.scanNetworkFiles = true;
        def.scan.heuristicLevel = 2;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = false;
        def.notifications.showScanProgress = false;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = false;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::Server] = std::move(def);
    }

    // --- Developer ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::Developer;
        def.description = "Reduced scanning for developer workstations";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 30;
        def.resources.maxMemoryMb = 384;
        def.resources.ioPriority = 1;
        def.resources.maxConcurrentScans = 1;
        def.resources.backgroundMode = false;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = false;
        def.scan.scanArchives = false;
        def.scan.maxArchiveDepth = 3;
        def.scan.scanNetworkFiles = false;
        def.scan.heuristicLevel = 1;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = true;
        def.notifications.showScanProgress = true;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = true;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::Developer] = std::move(def);
    }

    // --- LockedDown ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::LockedDown;
        def.description = "Maximum security with aggressive scanning";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 75;
        def.resources.maxMemoryMb = 1024;
        def.resources.ioPriority = 4;
        def.resources.maxConcurrentScans = 4;
        def.resources.backgroundMode = false;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = true;
        def.scan.scanArchives = true;
        def.scan.maxArchiveDepth = 10;
        def.scan.scanNetworkFiles = true;
        def.scan.heuristicLevel = 4;
        def.scan.cloudLookupEnabled = true;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = true;
        def.notifications.showScanProgress = true;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = true;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::LockedDown] = std::move(def);
    }

    // --- Gaming ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::Gaming;
        def.description = "Minimal resource usage for gaming sessions";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 10;
        def.resources.maxMemoryMb = 128;
        def.resources.ioPriority = 0;
        def.resources.maxConcurrentScans = 1;
        def.resources.backgroundMode = true;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = false;
        def.scan.scanArchives = false;
        def.scan.maxArchiveDepth = 0;
        def.scan.scanNetworkFiles = false;
        def.scan.heuristicLevel = 1;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = false;
        def.notifications.soundEnabled = false;
        def.notifications.showScanProgress = false;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = false;
        def.notifications.doNotDisturbEnabled = true;
        def.notifications.dndStartHour = 0;
        def.notifications.dndEndHour = 23;

        m_builtInProfiles[SystemProfile::Gaming] = std::move(def);
    }

    // --- LowResource ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::LowResource;
        def.description = "Minimal resource consumption for constrained environments";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 15;
        def.resources.maxMemoryMb = 128;
        def.resources.ioPriority = 0;
        def.resources.maxConcurrentScans = 1;
        def.resources.backgroundMode = true;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = false;
        def.scan.scanArchives = false;
        def.scan.maxArchiveDepth = 0;
        def.scan.scanNetworkFiles = false;
        def.scan.heuristicLevel = 1;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = false;
        def.notifications.showScanProgress = false;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = false;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::LowResource] = std::move(def);
    }

    // --- HighSecurity ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::HighSecurity;
        def.description = "Maximum detection capability, performance secondary";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 80;
        def.resources.maxMemoryMb = 1024;
        def.resources.ioPriority = 5;
        def.resources.maxConcurrentScans = 4;
        def.resources.backgroundMode = false;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = true;
        def.scan.scanArchives = true;
        def.scan.maxArchiveDepth = 15;
        def.scan.scanNetworkFiles = true;
        def.scan.heuristicLevel = 4;
        def.scan.cloudLookupEnabled = true;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = true;
        def.notifications.showScanProgress = true;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = true;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::HighSecurity] = std::move(def);
    }

    // --- Portable ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::Portable;
        def.description = "Profile for USB/portable installations";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 20;
        def.resources.maxMemoryMb = 256;
        def.resources.ioPriority = 1;
        def.resources.maxConcurrentScans = 1;
        def.resources.backgroundMode = false;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = true;
        def.scan.scanArchives = true;
        def.scan.maxArchiveDepth = 5;
        def.scan.scanNetworkFiles = false;
        def.scan.heuristicLevel = 2;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = true;
        def.notifications.showScanProgress = true;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = true;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::Portable] = std::move(def);
    }

    // --- Silent ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::Silent;
        def.description = "All notifications suppressed, do-not-disturb 24/7";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 25;
        def.resources.maxMemoryMb = 256;
        def.resources.ioPriority = 1;
        def.resources.maxConcurrentScans = 1;
        def.resources.backgroundMode = false;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = true;
        def.scan.scanArchives = true;
        def.scan.maxArchiveDepth = 5;
        def.scan.scanNetworkFiles = false;
        def.scan.heuristicLevel = 2;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = false;
        def.notifications.soundEnabled = false;
        def.notifications.showScanProgress = false;
        def.notifications.showThreatAlerts = false;
        def.notifications.showUpdateNotifications = false;
        def.notifications.doNotDisturbEnabled = true;
        def.notifications.dndStartHour = 0;
        def.notifications.dndEndHour = 23;

        m_builtInProfiles[SystemProfile::Silent] = std::move(def);
    }

    // --- Emergency ---
    {
        ProfileDefinition def;
        def.profileType = SystemProfile::Emergency;
        def.description = "Failsafe/recovery mode with minimal resource usage";
        def.isBuiltIn = true;
        def.isReadOnly = true;
        def.createdAt = now;
        def.modifiedAt = now;

        def.resources.maxCpuPercent = 5;
        def.resources.maxMemoryMb = 64;
        def.resources.ioPriority = 0;
        def.resources.maxConcurrentScans = 1;
        def.resources.backgroundMode = true;

        def.scan.realtimeProtection = true;
        def.scan.behaviorMonitoring = false;
        def.scan.scanArchives = false;
        def.scan.maxArchiveDepth = 0;
        def.scan.scanNetworkFiles = false;
        def.scan.heuristicLevel = 0;
        def.scan.cloudLookupEnabled = false;

        def.notifications.enabled = true;
        def.notifications.soundEnabled = false;
        def.notifications.showScanProgress = false;
        def.notifications.showThreatAlerts = true;
        def.notifications.showUpdateNotifications = false;
        def.notifications.doNotDisturbEnabled = false;

        m_builtInProfiles[SystemProfile::Emergency] = std::move(def);
    }
}

// ============================================================================
// STRUCT METHOD IMPLEMENTATIONS
// ============================================================================

// --- ResourceLimits ---

std::string ResourceLimits::ToJson() const
{
    try {
        Json j;
        j["maxCpuPercent"] = maxCpuPercent;
        j["maxMemoryMb"] = maxMemoryMb;
        j["ioPriority"] = ioPriority;
        j["maxConcurrentScans"] = maxConcurrentScans;
        j["scanThreadPriority"] = scanThreadPriority;
        j["backgroundMode"] = backgroundMode;
        j["networkBandwidthKbps"] = networkBandwidthKbps;
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ProfileScanSettings ---

std::string ProfileScanSettings::ToJson() const
{
    try {
        Json j;
        j["realtimeProtection"] = realtimeProtection;
        j["behaviorMonitoring"] = behaviorMonitoring;
        j["scanArchives"] = scanArchives;
        j["maxArchiveDepth"] = maxArchiveDepth;
        j["scanNetworkFiles"] = scanNetworkFiles;
        j["scanOnAccess"] = scanOnAccess;
        j["scanOnExecute"] = scanOnExecute;
        j["scanOnWrite"] = scanOnWrite;
        j["heuristicLevel"] = heuristicLevel;
        j["cloudLookupEnabled"] = cloudLookupEnabled;
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ProfileNotificationSettings ---

std::string ProfileNotificationSettings::ToJson() const
{
    try {
        Json j;
        j["enabled"] = enabled;
        j["soundEnabled"] = soundEnabled;
        j["showScanProgress"] = showScanProgress;
        j["showThreatAlerts"] = showThreatAlerts;
        j["showUpdateNotifications"] = showUpdateNotifications;
        j["displayDurationSeconds"] = displayDurationSeconds;
        j["doNotDisturbEnabled"] = doNotDisturbEnabled;
        j["dndStartHour"] = dndStartHour;
        j["dndEndHour"] = dndEndHour;
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ProfileDefinition ---

bool ProfileDefinition::IsValid() const noexcept
{
    if (profileType == SystemProfile::Custom && customName.empty()) {
        return false;
    }
    if (profileType == SystemProfile::Custom &&
        customName.size() > ProfileConstants::MAX_PROFILE_NAME_LENGTH) {
        return false;
    }
    if (resources.maxCpuPercent > 100) {
        return false;
    }
    if (resources.ioPriority > 5) {
        return false;
    }
    if (scan.heuristicLevel > 4) {
        return false;
    }
    return true;
}

std::string ProfileDefinition::ToJson() const
{
    try {
        Json j;
        j["profileType"] = std::string(GetSystemProfileName(profileType));
        j["customName"] = customName;
        j["description"] = description;
        j["resources"] = Json::parse(resources.ToJson());
        j["scan"] = Json::parse(scan.ToJson());
        j["notifications"] = Json::parse(notifications.ToJson());
        j["isBuiltIn"] = isBuiltIn;
        j["isReadOnly"] = isReadOnly;

        {
            Json excl = Json::array();
            for (const auto& p : pathExclusions) {
                excl.push_back(WideToUtf8(p));
            }
            j["pathExclusions"] = std::move(excl);
        }
        {
            Json excl = Json::array();
            for (const auto& p : processExclusions) {
                excl.push_back(WideToUtf8(p));
            }
            j["processExclusions"] = std::move(excl);
        }
        {
            Json excl = Json::array();
            for (const auto& p : extensionExclusions) {
                excl.push_back(WideToUtf8(p));
            }
            j["extensionExclusions"] = std::move(excl);
        }
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ProfileSwitchEvent ---

std::string ProfileSwitchEvent::ToJson() const
{
    try {
        Json j;
        j["previousProfile"] = std::string(GetSystemProfileName(previousProfile));
        j["newProfile"] = std::string(GetSystemProfileName(newProfile));
        j["trigger"] = std::string(GetProfileTriggerName(trigger));
        j["switchDurationMs"] = switchDurationMs;
        j["success"] = success;
        j["errorMessage"] = errorMessage;

        auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()).count();
        j["timestampMs"] = epoch;

        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ProfileScheduleEntry ---

bool ProfileScheduleEntry::IsActiveNow() const
{
    if (!enabled) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm localTm{};
#ifdef _WIN32
    localtime_s(&localTm, &nowTime);
#else
    localtime_r(&nowTime, &localTm);
#endif

    // Check day-of-week bitmask (tm_wday: 0=Sunday)
    const uint8_t dayBit = static_cast<uint8_t>(1u << localTm.tm_wday);
    if ((daysOfWeek & dayBit) == 0) {
        return false;
    }

    const uint32_t currentMinutes =
        static_cast<uint32_t>(localTm.tm_hour) * 60 +
        static_cast<uint32_t>(localTm.tm_min);
    const uint32_t startMinutes = startHour * 60 + startMinute;
    const uint32_t endMinutes = endHour * 60 + endMinute;

    if (startMinutes <= endMinutes) {
        return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    }
    // Wraps midnight
    return currentMinutes >= startMinutes || currentMinutes <= endMinutes;
}

std::string ProfileScheduleEntry::ToJson() const
{
    try {
        Json j;
        j["scheduleId"] = scheduleId;
        j["profile"] = std::string(GetSystemProfileName(profile));
        j["daysOfWeek"] = daysOfWeek;
        j["startHour"] = startHour;
        j["startMinute"] = startMinute;
        j["endHour"] = endHour;
        j["endMinute"] = endMinute;
        j["enabled"] = enabled;
        j["priority"] = priority;
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ApplicationTriggerRule ---

std::string ApplicationTriggerRule::ToJson() const
{
    try {
        Json j;
        j["ruleId"] = ruleId;
        j["applicationPattern"] = WideToUtf8(applicationPattern);
        j["profileWhenRunning"] = std::string(GetSystemProfileName(profileWhenRunning));
        j["profileAfterExit"] = std::string(GetSystemProfileName(profileAfterExit));
        j["switchDelaySeconds"] = switchDelaySeconds;
        j["exitDelaySeconds"] = exitDelaySeconds;
        j["enabled"] = enabled;
        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ProfileStatistics ---

void ProfileStatistics::Reset() noexcept
{
    profileSwitches.store(0, std::memory_order_relaxed);
    manualSwitches.store(0, std::memory_order_relaxed);
    scheduledSwitches.store(0, std::memory_order_relaxed);
    applicationTriggers.store(0, std::memory_order_relaxed);
    emergencySwitches.store(0, std::memory_order_relaxed);
    switchFailures.store(0, std::memory_order_relaxed);
    for (auto& t : timeInProfile) {
        t.store(0, std::memory_order_relaxed);
    }
    startTime = Clock::now();
}

std::string ProfileStatistics::ToJson() const
{
    try {
        Json j;
        j["profileSwitches"] = profileSwitches.load(std::memory_order_relaxed);
        j["manualSwitches"] = manualSwitches.load(std::memory_order_relaxed);
        j["scheduledSwitches"] = scheduledSwitches.load(std::memory_order_relaxed);
        j["applicationTriggers"] = applicationTriggers.load(std::memory_order_relaxed);
        j["emergencySwitches"] = emergencySwitches.load(std::memory_order_relaxed);
        j["switchFailures"] = switchFailures.load(std::memory_order_relaxed);

        Json arr = Json::array();
        for (size_t i = 0; i < timeInProfile.size(); ++i) {
            arr.push_back(timeInProfile[i].load(std::memory_order_relaxed));
        }
        j["timeInProfileSeconds"] = std::move(arr);

        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - startTime).count();
        j["uptimeSeconds"] = uptime;

        return j.dump(2);
    }
    catch (...) {
        return "{}";
    }
}

// --- ProfileManagerConfiguration ---

bool ProfileManagerConfiguration::IsValid() const noexcept
{
    if (autoDetectIntervalSeconds == 0) {
        return false;
    }
    if (static_cast<uint8_t>(initialProfile) > static_cast<uint8_t>(SystemProfile::Custom)) {
        return false;
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetSystemProfileName(SystemProfile profile) noexcept
{
    switch (profile) {
    case SystemProfile::Standard:     return "Standard";
    case SystemProfile::Server:       return "Server";
    case SystemProfile::Developer:    return "Developer";
    case SystemProfile::LockedDown:   return "LockedDown";
    case SystemProfile::Gaming:       return "Gaming";
    case SystemProfile::LowResource:  return "LowResource";
    case SystemProfile::HighSecurity: return "HighSecurity";
    case SystemProfile::Portable:     return "Portable";
    case SystemProfile::Silent:       return "Silent";
    case SystemProfile::Emergency:    return "Emergency";
    case SystemProfile::Custom:       return "Custom";
    default:                          return "Unknown";
    }
}

std::string_view GetMachineRoleName(MachineRole role) noexcept
{
    switch (role) {
    case MachineRole::Unknown:          return "Unknown";
    case MachineRole::Workstation:      return "Workstation";
    case MachineRole::Server:           return "Server";
    case MachineRole::DomainController: return "DomainController";
    case MachineRole::VirtualMachine:   return "VirtualMachine";
    case MachineRole::Terminal:         return "Terminal";
    case MachineRole::Laptop:           return "Laptop";
    case MachineRole::Tablet:           return "Tablet";
    case MachineRole::IoTDevice:        return "IoTDevice";
    case MachineRole::Container:        return "Container";
    default:                            return "Unknown";
    }
}

std::string_view GetProfileTriggerName(ProfileTrigger trigger) noexcept
{
    switch (trigger) {
    case ProfileTrigger::Manual:            return "Manual";
    case ProfileTrigger::Scheduled:         return "Scheduled";
    case ProfileTrigger::ApplicationStart:  return "ApplicationStart";
    case ProfileTrigger::PowerEvent:        return "PowerEvent";
    case ProfileTrigger::NetworkChange:     return "NetworkChange";
    case ProfileTrigger::UserActivity:      return "UserActivity";
    case ProfileTrigger::ResourcePressure:  return "ResourcePressure";
    case ProfileTrigger::PolicyUpdate:      return "PolicyUpdate";
    case ProfileTrigger::Emergency:         return "Emergency";
    default:                                return "Unknown";
    }
}

SystemProfile GetDefaultProfileForRole(MachineRole role)
{
    switch (role) {
    case MachineRole::Server:           return SystemProfile::Server;
    case MachineRole::DomainController: return SystemProfile::HighSecurity;
    case MachineRole::VirtualMachine:   return SystemProfile::LowResource;
    case MachineRole::Terminal:         return SystemProfile::Server;
    case MachineRole::Laptop:           return SystemProfile::Standard;
    case MachineRole::Container:        return SystemProfile::LowResource;
    case MachineRole::Workstation:
    case MachineRole::Unknown:
    default:
        return SystemProfile::Standard;
    }
}

// ============================================================================
// PROFILEMANAGER — STATIC MEMBERS
// ============================================================================

std::atomic<bool> ProfileManager::s_instanceCreated{ false };

// ============================================================================
// PROFILEMANAGER — SINGLETON
// ============================================================================

ProfileManager& ProfileManager::Instance() noexcept
{
    static ProfileManager instance;
    return instance;
}

bool ProfileManager::HasInstance() noexcept
{
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// PROFILEMANAGER — CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProfileManager::ProfileManager()
    : m_impl(std::make_unique<ProfileManagerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

ProfileManager::~ProfileManager()
{
    Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

// ============================================================================
// PROFILEMANAGER — LIFECYCLE
// ============================================================================

bool ProfileManager::Initialize(const ProfileManagerConfiguration& config)
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status == ProfileStatus::Running) {
        SS_LOG_WARN(kLogCategory, L"ProfileManager already initialized");
        return true;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"ProfileManager initialization failed: invalid configuration");
        m_impl->m_status = ProfileStatus::Error;
        return false;
    }

    m_impl->m_status = ProfileStatus::Initializing;
    m_impl->m_config = config;

    SS_LOG_INFO(kLogCategory, L"ProfileManager initializing (v%u.%u.%u)",
        ProfileConstants::VERSION_MAJOR,
        ProfileConstants::VERSION_MINOR,
        ProfileConstants::VERSION_PATCH);

    m_impl->PopulateBuiltInProfiles();

    m_currentProfile = config.initialProfile;
    m_impl->m_profileStartTime = Clock::now();
    m_impl->m_lastSwitchTime = TimePoint{};
    m_impl->m_stats.Reset();
    m_impl->m_emergencyMode.store(false, std::memory_order_relaxed);
    m_impl->m_shutdownRequested.store(false, std::memory_order_relaxed);

    m_impl->m_status = ProfileStatus::Running;

    SS_LOG_INFO(kLogCategory, L"ProfileManager initialized with profile: %hs",
        std::string(GetSystemProfileName(m_currentProfile)).c_str());

    return true;
}

void ProfileManager::Shutdown()
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status == ProfileStatus::Stopped ||
        m_impl->m_status == ProfileStatus::Uninitialized) {
        return;
    }

    SS_LOG_INFO(kLogCategory, L"ProfileManager shutting down");

    m_impl->m_status = ProfileStatus::Stopping;
    m_impl->m_shutdownRequested.store(true, std::memory_order_release);

    // Accumulate time for current profile
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - m_impl->m_profileStartTime).count();
    auto idx = static_cast<size_t>(m_currentProfile);
    if (idx < m_impl->m_stats.timeInProfile.size()) {
        m_impl->m_stats.timeInProfile[idx].fetch_add(
            static_cast<uint64_t>(elapsed), std::memory_order_relaxed);
    }

    m_impl->m_switchCallbacks.clear();
    m_impl->m_errorCallback = nullptr;
    m_impl->m_status = ProfileStatus::Stopped;

    SS_LOG_INFO(kLogCategory, L"ProfileManager shutdown complete");
}

bool ProfileManager::IsInitialized() const noexcept
{
    std::shared_lock lock(m_mutex);
    return m_impl->m_status == ProfileStatus::Running;
}

ProfileStatus ProfileManager::GetStatus() const noexcept
{
    std::shared_lock lock(m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// PROFILEMANAGER — ACTIVE PROFILE
// ============================================================================

bool ProfileManager::SetActiveProfile(SystemProfile profile)
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status != ProfileStatus::Running) {
        SS_LOG_ERROR(kLogCategory, L"Cannot switch profile: ProfileManager not running");
        return false;
    }

    // Emergency mode blocks all switches except to Emergency
    if (m_impl->m_emergencyMode.load(std::memory_order_acquire) &&
        profile != SystemProfile::Emergency) {
        SS_LOG_WARN(kLogCategory,
            L"Cannot switch to '%hs' while in emergency mode; exit emergency first",
            std::string(GetSystemProfileName(profile)).c_str());
        return false;
    }

    // No-op if already on this profile
    if (m_currentProfile == profile) {
        return true;
    }

    // Enforce cooldown (skip for Emergency)
    if (profile != SystemProfile::Emergency &&
        m_impl->m_lastSwitchTime != TimePoint{}) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - m_impl->m_lastSwitchTime).count();
        if (elapsed < static_cast<long long>(m_impl->m_config.switchCooldownSeconds)) {
            SS_LOG_WARN(kLogCategory,
                L"Profile switch cooldown active (%lld/%u seconds elapsed)",
                static_cast<long long>(elapsed),
                m_impl->m_config.switchCooldownSeconds);
            m_impl->m_stats.switchFailures.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    // Validate target profile exists
    if (profile != SystemProfile::Custom &&
        m_impl->m_builtInProfiles.find(profile) == m_impl->m_builtInProfiles.end()) {
        SS_LOG_ERROR(kLogCategory, L"Target profile '%hs' not found in built-in profiles",
            std::string(GetSystemProfileName(profile)).c_str());
        m_impl->m_stats.switchFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    auto switchStart = Clock::now();

    // Accumulate time for outgoing profile
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            switchStart - m_impl->m_profileStartTime).count();
        auto idx = static_cast<size_t>(m_currentProfile);
        if (idx < m_impl->m_stats.timeInProfile.size()) {
            m_impl->m_stats.timeInProfile[idx].fetch_add(
                static_cast<uint64_t>(elapsed), std::memory_order_relaxed);
        }
    }

    ProfileSwitchEvent evt;
    evt.previousProfile = m_currentProfile;
    evt.newProfile = profile;
    evt.trigger = (profile == SystemProfile::Emergency)
        ? ProfileTrigger::Emergency
        : ProfileTrigger::Manual;
    evt.timestamp = std::chrono::system_clock::now();
    evt.success = true;

    SystemProfile previous = m_currentProfile;
    m_currentProfile = profile;
    m_impl->m_profileStartTime = Clock::now();
    m_impl->m_lastSwitchTime = m_impl->m_profileStartTime;

    auto switchEnd = Clock::now();
    evt.switchDurationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(switchEnd - switchStart).count());

    // Record in history (cap at 1000)
    m_impl->m_switchHistory.push_back(evt);
    if (m_impl->m_switchHistory.size() > 1000) {
        m_impl->m_switchHistory.erase(m_impl->m_switchHistory.begin());
    }

    // Update stats
    m_impl->m_stats.profileSwitches.fetch_add(1, std::memory_order_relaxed);
    if (evt.trigger == ProfileTrigger::Emergency) {
        m_impl->m_stats.emergencySwitches.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_impl->m_stats.manualSwitches.fetch_add(1, std::memory_order_relaxed);
    }

    SS_LOG_INFO(kLogCategory, L"Profile switched: '%hs' -> '%hs' (%u ms)",
        std::string(GetSystemProfileName(previous)).c_str(),
        std::string(GetSystemProfileName(profile)).c_str(),
        evt.switchDurationMs);

    // Fire callbacks (copy map to allow safe iteration if callback modifies registration)
    auto callbacks = m_impl->m_switchCallbacks;
    lock.unlock();

    for (const auto& [id, cb] : callbacks) {
        try {
            if (cb) cb(evt);
        }
        catch (...) {
            SS_LOG_ERROR(kLogCategory,
                L"Exception in profile switch callback id=%llu", static_cast<unsigned long long>(id));
        }
    }

    return true;
}

bool ProfileManager::SetActiveProfile(const std::string& profileName)
{
    {
        std::unique_lock lock(m_mutex);

        if (m_impl->m_status != ProfileStatus::Running) {
            SS_LOG_ERROR(kLogCategory, L"Cannot switch profile: ProfileManager not running");
            return false;
        }

        auto it = m_impl->m_customProfiles.find(profileName);
        if (it == m_impl->m_customProfiles.end()) {
            SS_LOG_ERROR(kLogCategory, L"Custom profile '%hs' not found", profileName.c_str());
            return false;
        }

        m_impl->m_activeCustomProfileName = profileName;
    }

    return SetActiveProfile(SystemProfile::Custom);
}

SystemProfile ProfileManager::GetActiveProfile() const noexcept
{
    std::shared_lock lock(m_mutex);
    return m_currentProfile;
}

ProfileDefinition ProfileManager::GetActiveProfileDefinition() const
{
    std::shared_lock lock(m_mutex);

    // If a custom profile is active, return it
    if (m_currentProfile == SystemProfile::Custom &&
        !m_impl->m_activeCustomProfileName.empty()) {
        auto cit = m_impl->m_customProfiles.find(m_impl->m_activeCustomProfileName);
        if (cit != m_impl->m_customProfiles.end()) {
            return cit->second;
        }
    }

    auto it = m_impl->m_builtInProfiles.find(m_currentProfile);
    if (it != m_impl->m_builtInProfiles.end()) {
        return it->second;
    }

    // Fallback to Standard if current profile is somehow missing
    auto fallback = m_impl->m_builtInProfiles.find(SystemProfile::Standard);
    if (fallback != m_impl->m_builtInProfiles.end()) {
        return fallback->second;
    }

    return ProfileDefinition{};
}

std::string ProfileManager::GetActiveProfileName() const
{
    std::shared_lock lock(m_mutex);
    return std::string(GetSystemProfileName(m_currentProfile));
}

// ============================================================================
// PROFILEMANAGER — PROFILE MANAGEMENT
// ============================================================================

ProfileDefinition ProfileManager::GetProfileDefinition(SystemProfile profile) const
{
    std::shared_lock lock(m_mutex);

    auto it = m_impl->m_builtInProfiles.find(profile);
    if (it != m_impl->m_builtInProfiles.end()) {
        return it->second;
    }

    SS_LOG_WARN(kLogCategory, L"Profile definition not found for '%hs'",
        std::string(GetSystemProfileName(profile)).c_str());
    return ProfileDefinition{};
}

std::optional<ProfileDefinition> ProfileManager::GetCustomProfile(const std::string& name) const
{
    std::shared_lock lock(m_mutex);

    auto it = m_impl->m_customProfiles.find(name);
    if (it != m_impl->m_customProfiles.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool ProfileManager::CreateCustomProfile(const ProfileDefinition& profile)
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status != ProfileStatus::Running) {
        SS_LOG_ERROR(kLogCategory, L"Cannot create profile: ProfileManager not running");
        return false;
    }

    if (!profile.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Cannot create profile: definition is invalid");
        return false;
    }

    if (profile.customName.empty()) {
        SS_LOG_ERROR(kLogCategory, L"Cannot create custom profile: name is empty");
        return false;
    }

    if (m_impl->m_customProfiles.size() >= ProfileConstants::MAX_CUSTOM_PROFILES) {
        SS_LOG_ERROR(kLogCategory,
            L"Cannot create custom profile: limit of %u reached",
            ProfileConstants::MAX_CUSTOM_PROFILES);
        return false;
    }

    if (m_impl->m_customProfiles.count(profile.customName) > 0) {
        SS_LOG_ERROR(kLogCategory, L"Custom profile '%hs' already exists",
            profile.customName.c_str());
        return false;
    }

    ProfileDefinition def = profile;
    def.profileType = SystemProfile::Custom;
    def.isBuiltIn = false;
    def.createdAt = std::chrono::system_clock::now();
    def.modifiedAt = def.createdAt;

    m_impl->m_customProfiles[def.customName] = std::move(def);

    SS_LOG_INFO(kLogCategory, L"Custom profile created: '%hs'", profile.customName.c_str());
    return true;
}

bool ProfileManager::UpdateCustomProfile(const std::string& name, const ProfileDefinition& profile)
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status != ProfileStatus::Running) {
        SS_LOG_ERROR(kLogCategory, L"Cannot update profile: ProfileManager not running");
        return false;
    }

    auto it = m_impl->m_customProfiles.find(name);
    if (it == m_impl->m_customProfiles.end()) {
        SS_LOG_ERROR(kLogCategory, L"Custom profile '%hs' not found for update", name.c_str());
        return false;
    }

    if (!profile.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Cannot update profile: definition is invalid");
        return false;
    }

    ProfileDefinition updated = profile;
    updated.profileType = SystemProfile::Custom;
    updated.isBuiltIn = false;
    updated.customName = name;
    updated.createdAt = it->second.createdAt;
    updated.modifiedAt = std::chrono::system_clock::now();

    it->second = std::move(updated);

    SS_LOG_INFO(kLogCategory, L"Custom profile updated: '%hs'", name.c_str());
    return true;
}

bool ProfileManager::DeleteCustomProfile(const std::string& name)
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status != ProfileStatus::Running) {
        SS_LOG_ERROR(kLogCategory, L"Cannot delete profile: ProfileManager not running");
        return false;
    }

    auto it = m_impl->m_customProfiles.find(name);
    if (it == m_impl->m_customProfiles.end()) {
        SS_LOG_WARN(kLogCategory, L"Custom profile '%hs' not found for deletion", name.c_str());
        return false;
    }

    m_impl->m_customProfiles.erase(it);
    SS_LOG_INFO(kLogCategory, L"Custom profile deleted: '%hs'", name.c_str());
    return true;
}

std::vector<ProfileDefinition> ProfileManager::ListProfiles() const
{
    std::shared_lock lock(m_mutex);

    std::vector<ProfileDefinition> result;
    result.reserve(m_impl->m_builtInProfiles.size() + m_impl->m_customProfiles.size());

    for (const auto& [type, def] : m_impl->m_builtInProfiles) {
        result.push_back(def);
    }
    for (const auto& [name, def] : m_impl->m_customProfiles) {
        result.push_back(def);
    }

    return result;
}

std::vector<std::string> ProfileManager::ListCustomProfileNames() const
{
    std::shared_lock lock(m_mutex);

    std::vector<std::string> names;
    names.reserve(m_impl->m_customProfiles.size());
    for (const auto& [name, def] : m_impl->m_customProfiles) {
        names.push_back(name);
    }
    return names;
}

// ============================================================================
// PROFILEMANAGER — AUTO-DETECTION
// ============================================================================

MachineRole ProfileManager::DetectMachineRole() const
{
    // 1. Check if server OS
    Utils::SystemUtils::OSVersion osv{};
    if (Utils::SystemUtils::QueryOSVersion(osv) && osv.isServer) {
        // 2. Check for domain controller
        DSROLE_PRIMARY_DOMAIN_INFO_BASIC* pInfo = nullptr;
        DWORD dwErr = DsRoleGetPrimaryDomainInformation(
            nullptr,
            DsRolePrimaryDomainInfoBasic,
            reinterpret_cast<PBYTE*>(&pInfo));
        if (dwErr == ERROR_SUCCESS && pInfo != nullptr) {
            bool isDC = (pInfo->MachineRole == DsRole_RolePrimaryDomainController ||
                         pInfo->MachineRole == DsRole_RoleBackupDomainController);
            DsRoleFreeMemory(pInfo);
            if (isDC) {
                SS_LOG_INFO(kLogCategory, L"Machine role detected: DomainController");
                return MachineRole::DomainController;
            }
        }

        SS_LOG_INFO(kLogCategory, L"Machine role detected: Server");
        return MachineRole::Server;
    }

    // 3. Check if virtual machine (hypervisor bit or CPU brand)
    Utils::SystemUtils::CpuInfo cpuInfo{};
    if (Utils::SystemUtils::QueryCpuInfo(cpuInfo)) {
        std::wstring brandLower = cpuInfo.brand;
        std::transform(brandLower.begin(), brandLower.end(), brandLower.begin(), ::towlower);
        if (brandLower.find(L"virtual") != std::wstring::npos ||
            brandLower.find(L"vmware") != std::wstring::npos ||
            brandLower.find(L"hyperv") != std::wstring::npos ||
            brandLower.find(L"kvm") != std::wstring::npos ||
            brandLower.find(L"xen") != std::wstring::npos ||
            brandLower.find(L"qemu") != std::wstring::npos) {
            SS_LOG_INFO(kLogCategory, L"Machine role detected: VirtualMachine (CPU brand: '%ls')",
                cpuInfo.brand.c_str());
            return MachineRole::VirtualMachine;
        }
    }

    // 4. Check for hypervisor via CPUID (ECX bit 31 of leaf 1)
    {
        int regs[4]{};
        __cpuid(regs, 1);
        if (regs[2] & (1 << 31)) {
            SS_LOG_INFO(kLogCategory, L"Machine role detected: VirtualMachine (hypervisor CPUID bit)");
            return MachineRole::VirtualMachine;
        }
    }

    // 5. Check battery presence (laptop detection)
    {
        SYSTEM_POWER_STATUS powerStatus{};
        if (GetSystemPowerStatus(&powerStatus)) {
            // BatteryFlag != 128 (no battery) and != 255 (unknown)
            if (powerStatus.BatteryFlag != 128 &&
                powerStatus.BatteryFlag != 255) {
                SS_LOG_INFO(kLogCategory, L"Machine role detected: Laptop (battery present)");
                return MachineRole::Laptop;
            }
        }
    }

    SS_LOG_INFO(kLogCategory, L"Machine role detected: Workstation (default)");
    return MachineRole::Workstation;
}

SystemProfile ProfileManager::GetRecommendedProfile() const
{
    MachineRole role = DetectMachineRole();
    return GetDefaultProfileForRole(role);
}

bool ProfileManager::ApplyRecommendedProfile()
{
    SystemProfile recommended = GetRecommendedProfile();
    SS_LOG_INFO(kLogCategory, L"Applying recommended profile: '%hs'",
        std::string(GetSystemProfileName(recommended)).c_str());
    return SetActiveProfile(recommended);
}

void ProfileManager::SetAutoDetectionEnabled(bool enabled)
{
    std::unique_lock lock(m_mutex);
    m_impl->m_config.enableAutoDetection = enabled;
    SS_LOG_INFO(kLogCategory, L"Auto-detection %ls", enabled ? L"enabled" : L"disabled");
}

bool ProfileManager::IsAutoDetectionEnabled() const noexcept
{
    std::shared_lock lock(m_mutex);
    return m_impl->m_config.enableAutoDetection;
}

// ============================================================================
// PROFILEMANAGER — SCHEDULING
// ============================================================================

uint64_t ProfileManager::AddScheduleEntry(const ProfileScheduleEntry& entry)
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status != ProfileStatus::Running) {
        SS_LOG_ERROR(kLogCategory, L"Cannot add schedule: ProfileManager not running");
        return 0;
    }

    constexpr size_t MAX_SCHEDULE_ENTRIES = 256;
    if (m_impl->m_scheduleEntries.size() >= MAX_SCHEDULE_ENTRIES) {
        SS_LOG_ERROR(kLogCategory, L"Cannot add schedule: limit of %zu reached", MAX_SCHEDULE_ENTRIES);
        return 0;
    }

    if (entry.startHour > 23 || entry.endHour > 23 ||
        entry.startMinute > 59 || entry.endMinute > 59) {
        SS_LOG_ERROR(kLogCategory, L"Invalid schedule time values: %02u:%02u-%02u:%02u",
            entry.startHour, entry.startMinute, entry.endHour, entry.endMinute);
        return 0;
    }

    if (entry.daysOfWeek == 0) {
        SS_LOG_WARN(kLogCategory, L"Schedule entry has no active days (daysOfWeek=0)");
    }

    ProfileScheduleEntry newEntry = entry;
    newEntry.scheduleId = m_impl->m_nextScheduleId++;
    m_impl->m_scheduleEntries.push_back(newEntry);

    SS_LOG_INFO(kLogCategory,
        L"Schedule entry added: id=%llu profile='%hs' days=0x%02X %02u:%02u-%02u:%02u",
        static_cast<unsigned long long>(newEntry.scheduleId),
        std::string(GetSystemProfileName(newEntry.profile)).c_str(),
        static_cast<unsigned>(newEntry.daysOfWeek),
        newEntry.startHour, newEntry.startMinute,
        newEntry.endHour, newEntry.endMinute);

    return newEntry.scheduleId;
}

bool ProfileManager::RemoveScheduleEntry(uint64_t scheduleId)
{
    std::unique_lock lock(m_mutex);

    auto it = std::find_if(m_impl->m_scheduleEntries.begin(),
                           m_impl->m_scheduleEntries.end(),
                           [scheduleId](const ProfileScheduleEntry& e) {
                               return e.scheduleId == scheduleId;
                           });

    if (it == m_impl->m_scheduleEntries.end()) {
        SS_LOG_WARN(kLogCategory, L"Schedule entry id=%llu not found for removal",
            static_cast<unsigned long long>(scheduleId));
        return false;
    }

    m_impl->m_scheduleEntries.erase(it);
    SS_LOG_INFO(kLogCategory, L"Schedule entry removed: id=%llu",
        static_cast<unsigned long long>(scheduleId));
    return true;
}

bool ProfileManager::UpdateScheduleEntry(const ProfileScheduleEntry& entry)
{
    std::unique_lock lock(m_mutex);

    auto it = std::find_if(m_impl->m_scheduleEntries.begin(),
                           m_impl->m_scheduleEntries.end(),
                           [&entry](const ProfileScheduleEntry& e) {
                               return e.scheduleId == entry.scheduleId;
                           });

    if (it == m_impl->m_scheduleEntries.end()) {
        SS_LOG_WARN(kLogCategory, L"Schedule entry id=%llu not found for update",
            static_cast<unsigned long long>(entry.scheduleId));
        return false;
    }

    *it = entry;
    SS_LOG_INFO(kLogCategory, L"Schedule entry updated: id=%llu",
        static_cast<unsigned long long>(entry.scheduleId));
    return true;
}

std::vector<ProfileScheduleEntry> ProfileManager::ListScheduleEntries() const
{
    std::shared_lock lock(m_mutex);
    return m_impl->m_scheduleEntries;
}

void ProfileManager::SetScheduledSwitchingEnabled(bool enabled)
{
    std::unique_lock lock(m_mutex);
    m_impl->m_config.enableScheduledSwitching = enabled;
    SS_LOG_INFO(kLogCategory, L"Scheduled switching %ls", enabled ? L"enabled" : L"disabled");
}

// ============================================================================
// PROFILEMANAGER — APPLICATION TRIGGERS
// ============================================================================

uint64_t ProfileManager::AddApplicationTrigger(const ApplicationTriggerRule& rule)
{
    std::unique_lock lock(m_mutex);

    if (m_impl->m_status != ProfileStatus::Running) {
        SS_LOG_ERROR(kLogCategory, L"Cannot add trigger: ProfileManager not running");
        return 0;
    }

    constexpr size_t MAX_APPLICATION_TRIGGERS = 256;
    if (m_impl->m_applicationTriggers.size() >= MAX_APPLICATION_TRIGGERS) {
        SS_LOG_ERROR(kLogCategory, L"Cannot add trigger: limit of %zu reached", MAX_APPLICATION_TRIGGERS);
        return 0;
    }

    ApplicationTriggerRule newRule = rule;
    newRule.ruleId = m_impl->m_nextTriggerId++;
    m_impl->m_applicationTriggers.push_back(newRule);

    SS_LOG_INFO(kLogCategory, L"Application trigger added: id=%llu pattern='%ls'",
        static_cast<unsigned long long>(newRule.ruleId),
        newRule.applicationPattern.c_str());

    return newRule.ruleId;
}

bool ProfileManager::RemoveApplicationTrigger(uint64_t ruleId)
{
    std::unique_lock lock(m_mutex);

    auto it = std::find_if(m_impl->m_applicationTriggers.begin(),
                           m_impl->m_applicationTriggers.end(),
                           [ruleId](const ApplicationTriggerRule& r) {
                               return r.ruleId == ruleId;
                           });

    if (it == m_impl->m_applicationTriggers.end()) {
        SS_LOG_WARN(kLogCategory, L"Application trigger id=%llu not found for removal",
            static_cast<unsigned long long>(ruleId));
        return false;
    }

    m_impl->m_applicationTriggers.erase(it);
    SS_LOG_INFO(kLogCategory, L"Application trigger removed: id=%llu",
        static_cast<unsigned long long>(ruleId));
    return true;
}

bool ProfileManager::UpdateApplicationTrigger(const ApplicationTriggerRule& rule)
{
    std::unique_lock lock(m_mutex);

    auto it = std::find_if(m_impl->m_applicationTriggers.begin(),
                           m_impl->m_applicationTriggers.end(),
                           [&rule](const ApplicationTriggerRule& r) {
                               return r.ruleId == rule.ruleId;
                           });

    if (it == m_impl->m_applicationTriggers.end()) {
        SS_LOG_WARN(kLogCategory, L"Application trigger id=%llu not found for update",
            static_cast<unsigned long long>(rule.ruleId));
        return false;
    }

    *it = rule;
    SS_LOG_INFO(kLogCategory, L"Application trigger updated: id=%llu",
        static_cast<unsigned long long>(rule.ruleId));
    return true;
}

std::vector<ApplicationTriggerRule> ProfileManager::ListApplicationTriggers() const
{
    std::shared_lock lock(m_mutex);
    return m_impl->m_applicationTriggers;
}

void ProfileManager::SetApplicationTriggersEnabled(bool enabled)
{
    std::unique_lock lock(m_mutex);
    m_impl->m_config.enableApplicationTriggers = enabled;
    SS_LOG_INFO(kLogCategory, L"Application triggers %ls", enabled ? L"enabled" : L"disabled");
}

// ============================================================================
// PROFILEMANAGER — RESOURCE LIMITS
// ============================================================================

ResourceLimits ProfileManager::GetCurrentResourceLimits() const
{
    std::shared_lock lock(m_mutex);

    if (m_impl->m_resourceOverride.has_value()) {
        return m_impl->m_resourceOverride.value();
    }

    auto it = m_impl->m_builtInProfiles.find(m_currentProfile);
    if (it != m_impl->m_builtInProfiles.end()) {
        return it->second.resources;
    }

    return ResourceLimits{};
}

void ProfileManager::OverrideResourceLimits(const ResourceLimits& limits)
{
    std::unique_lock lock(m_mutex);
    m_impl->m_resourceOverride = limits;
    SS_LOG_INFO(kLogCategory,
        L"Resource limits overridden: CPU=%u%% Mem=%uMB IO=%u Scans=%u",
        limits.maxCpuPercent, limits.maxMemoryMb,
        limits.ioPriority, limits.maxConcurrentScans);
}

void ProfileManager::ClearResourceOverride()
{
    std::unique_lock lock(m_mutex);
    m_impl->m_resourceOverride.reset();
    SS_LOG_INFO(kLogCategory, L"Resource limit override cleared");
}

// ============================================================================
// PROFILEMANAGER — FAILSAFE / EMERGENCY
// ============================================================================

bool ProfileManager::ActivateEmergencyProfile()
{
    SS_LOG_WARN(kLogCategory, L"Emergency profile activation requested");

    {
        std::unique_lock lock(m_mutex);
        if (m_impl->m_emergencyMode.load(std::memory_order_relaxed)) {
            SS_LOG_WARN(kLogCategory, L"Already in emergency mode");
            return true;
        }
        m_impl->m_preEmergencyProfile = m_currentProfile;
        m_impl->m_emergencyMode.store(true, std::memory_order_release);
    }

    return SetActiveProfile(SystemProfile::Emergency);
}

bool ProfileManager::IsInEmergencyMode() const noexcept
{
    return m_impl->m_emergencyMode.load(std::memory_order_acquire);
}

bool ProfileManager::ExitEmergencyMode()
{
    SystemProfile target;
    {
        std::unique_lock lock(m_mutex);

        if (!m_impl->m_emergencyMode.load(std::memory_order_relaxed)) {
            SS_LOG_WARN(kLogCategory, L"Not in emergency mode; nothing to exit");
            return false;
        }

        SS_LOG_INFO(kLogCategory, L"Exiting emergency mode");

        target = m_impl->m_preEmergencyProfile;
        if (target == SystemProfile::Emergency) {
            target = m_impl->m_config.initialProfile;
        }

        m_impl->m_emergencyMode.store(false, std::memory_order_release);
    }

    return SetActiveProfile(target);
}

// ============================================================================
// PROFILEMANAGER — CALLBACKS
// ============================================================================

uint64_t ProfileManager::RegisterSwitchCallback(ProfileSwitchCallback callback)
{
    std::unique_lock lock(m_mutex);

    if (!callback) {
        SS_LOG_WARN(kLogCategory, L"Attempted to register null switch callback");
        return 0;
    }

    uint64_t id = m_impl->m_nextCallbackId++;
    m_impl->m_switchCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(kLogCategory, L"Switch callback registered: id=%llu",
        static_cast<unsigned long long>(id));
    return id;
}

void ProfileManager::RegisterErrorCallback(ErrorCallback callback)
{
    std::unique_lock lock(m_mutex);
    m_impl->m_errorCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Error callback registered");
}

void ProfileManager::UnregisterCallback(uint64_t callbackId)
{
    std::unique_lock lock(m_mutex);

    auto it = m_impl->m_switchCallbacks.find(callbackId);
    if (it != m_impl->m_switchCallbacks.end()) {
        m_impl->m_switchCallbacks.erase(it);
        SS_LOG_DEBUG(kLogCategory, L"Switch callback unregistered: id=%llu",
            static_cast<unsigned long long>(callbackId));
    } else {
        SS_LOG_WARN(kLogCategory, L"Callback id=%llu not found for unregistration",
            static_cast<unsigned long long>(callbackId));
    }
}

// ============================================================================
// PROFILEMANAGER — STATISTICS
// ============================================================================

ProfileStatistics ProfileManager::GetStatistics() const
{
    std::shared_lock lock(m_mutex);
    return m_impl->m_stats;
}

void ProfileManager::ResetStatistics()
{
    std::unique_lock lock(m_mutex);
    m_impl->m_stats.Reset();
    SS_LOG_INFO(kLogCategory, L"Profile statistics reset");
}

std::vector<ProfileSwitchEvent> ProfileManager::GetSwitchHistory(size_t maxEntries) const
{
    std::shared_lock lock(m_mutex);

    if (maxEntries >= m_impl->m_switchHistory.size()) {
        return m_impl->m_switchHistory;
    }

    // Return the most recent entries
    return std::vector<ProfileSwitchEvent>(
        m_impl->m_switchHistory.end() - static_cast<ptrdiff_t>(maxEntries),
        m_impl->m_switchHistory.end());
}

// ============================================================================
// PROFILEMANAGER — SELF TEST & VERSION
// ============================================================================

bool ProfileManager::SelfTest()
{
    SS_LOG_INFO(kLogCategory, L"Running ProfileManager self-test");

    std::shared_lock lock(m_mutex);

    bool pass = true;

    // Verify all built-in profiles present
    constexpr SystemProfile expectedProfiles[] = {
        SystemProfile::Standard, SystemProfile::Server,
        SystemProfile::Developer, SystemProfile::LockedDown,
        SystemProfile::Gaming, SystemProfile::LowResource,
        SystemProfile::HighSecurity, SystemProfile::Portable,
        SystemProfile::Silent, SystemProfile::Emergency
    };

    for (auto p : expectedProfiles) {
        if (m_impl->m_builtInProfiles.find(p) == m_impl->m_builtInProfiles.end()) {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAIL: built-in profile '%hs' missing",
                std::string(GetSystemProfileName(p)).c_str());
            pass = false;
        }
    }

    // Validate each built-in profile definition
    for (const auto& [type, def] : m_impl->m_builtInProfiles) {
        if (!def.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAIL: profile '%hs' invalid definition",
                std::string(GetSystemProfileName(type)).c_str());
            pass = false;
        }
    }

    // Verify current profile exists in registry
    if (m_impl->m_builtInProfiles.find(m_currentProfile) == m_impl->m_builtInProfiles.end() &&
        m_currentProfile != SystemProfile::Custom) {
        SS_LOG_ERROR(kLogCategory, L"Self-test FAIL: active profile '%hs' not found",
            std::string(GetSystemProfileName(m_currentProfile)).c_str());
        pass = false;
    }

    if (pass) {
        SS_LOG_INFO(kLogCategory, L"ProfileManager self-test PASSED");
    } else {
        SS_LOG_ERROR(kLogCategory, L"ProfileManager self-test FAILED");
    }

    return pass;
}

std::string ProfileManager::GetVersionString() noexcept
{
    try {
        return std::format("{}.{}.{}", ProfileConstants::VERSION_MAJOR,
            ProfileConstants::VERSION_MINOR, ProfileConstants::VERSION_PATCH);
    }
    catch (...) {
        return "0.0.0";
    }
}

}  // namespace Config
}  // namespace ShadowStrike
