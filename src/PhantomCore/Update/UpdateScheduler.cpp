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

#include "UpdateScheduler.hpp"

#include <sstream>
#include <thread>
#include <shared_mutex>
#include <condition_variable>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <shellapi.h>

// For network adapter enumeration: winsock2 must precede iphlpapi.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// ANONYMOUS NAMESPACE — internal helpers
// ============================================================================

namespace {

constexpr const wchar_t* kLogCategory = L"Scheduler";

// ---------------------------------------------------------------------------
// JSON helpers (match RollbackManager.cpp / UpdateVerifier.cpp conventions)
// ---------------------------------------------------------------------------

[[nodiscard]] std::string JsonEscape(const std::string& s) noexcept {
    std::string out;
    out.reserve(s.size() + 8);
    for (const char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char hex[8];
                (void)std::snprintf(hex, sizeof(hex), "\\u%04x",
                    static_cast<unsigned>(static_cast<unsigned char>(c)));
                out += hex;
            } else {
                out += c;
            }
            break;
        }
    }
    return out;
}

[[nodiscard]] std::string FormatIso8601(
    const std::chrono::system_clock::time_point& tp) noexcept
{
    try {
        const auto tt = std::chrono::system_clock::to_time_t(tp);
        std::tm tmBuf{};
        if (gmtime_s(&tmBuf, &tt) != 0) return "1970-01-01T00:00:00Z";
        char buf[32]{};
        if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf) == 0)
            return "1970-01-01T00:00:00Z";
        return std::string(buf);
    }
    catch (...) { return "1970-01-01T00:00:00Z"; }
}

// Get current local time-of-day in minutes from midnight.
[[nodiscard]] uint16_t CurrentMinutesFromMidnight() noexcept {
    const auto now    = std::chrono::system_clock::now();
    const auto tt     = std::chrono::system_clock::to_time_t(now);
    std::tm localTm{};
    if (localtime_s(&localTm, &tt) != 0) return 0;
    return static_cast<uint16_t>(localTm.tm_hour * 60 + localTm.tm_min);
}

// Get current day-of-week as a bitmask bit (bit 0 = Sunday).
[[nodiscard]] uint8_t CurrentDayBit() noexcept {
    const auto now = std::chrono::system_clock::now();
    const auto tt  = std::chrono::system_clock::to_time_t(now);
    std::tm localTm{};
    if (localtime_s(&localTm, &tt) != 0) return 0;
    return static_cast<uint8_t>(1u << localTm.tm_wday);
}

// Query CPU usage via GetSystemTimes (returns percentage 0-100).
[[nodiscard]] uint8_t QueryCpuUsage() noexcept {
    static ULARGE_INTEGER sPrevIdle{}, sPrevKernel{}, sPrevUser{};

    FILETIME ftIdle{}, ftKernel{}, ftUser{};
    if (!::GetSystemTimes(&ftIdle, &ftKernel, &ftUser)) return 0;

    ULARGE_INTEGER curIdle, curKernel, curUser;
    std::memcpy(&curIdle,   &ftIdle,   sizeof(ULARGE_INTEGER));
    std::memcpy(&curKernel, &ftKernel, sizeof(ULARGE_INTEGER));
    std::memcpy(&curUser,   &ftUser,   sizeof(ULARGE_INTEGER));

    const auto idleDelta   = curIdle.QuadPart   - sPrevIdle.QuadPart;
    const auto kernelDelta = curKernel.QuadPart - sPrevKernel.QuadPart;
    const auto userDelta   = curUser.QuadPart   - sPrevUser.QuadPart;

    sPrevIdle   = curIdle;
    sPrevKernel = curKernel;
    sPrevUser   = curUser;

    const auto totalDelta = kernelDelta + userDelta;
    if (totalDelta == 0) return 0;

    const auto busyDelta = totalDelta - idleDelta;
    return static_cast<uint8_t>((busyDelta * 100) / totalDelta);
}

// Query battery status.
struct BatteryInfo { bool onBattery; uint8_t percent; };
[[nodiscard]] BatteryInfo QueryBatteryStatus() noexcept {
    SYSTEM_POWER_STATUS sps{};
    if (!::GetSystemPowerStatus(&sps)) return { false, 100 };
    const bool onBattery = (sps.ACLineStatus == 0);
    const uint8_t pct = (sps.BatteryLifePercent <= 100)
        ? sps.BatteryLifePercent : 100;
    return { onBattery, pct };
}

// Query full-screen / presentation / gaming mode via SHQueryUserNotificationState.
struct UserModeInfo { bool gaming; bool presenting; };
[[nodiscard]] UserModeInfo QueryUserMode() noexcept {
    QUERY_USER_NOTIFICATION_STATE quns = QUNS_ACCEPTS_NOTIFICATIONS;
    const HRESULT hr = ::SHQueryUserNotificationState(&quns);
    if (FAILED(hr)) return { false, false };
    const bool gaming    = (quns == QUNS_RUNNING_D3D_FULL_SCREEN);
    const bool presenting = (quns == QUNS_BUSY ||
                             quns == QUNS_PRESENTATION_MODE);
    return { gaming, presenting };
}

// Approximate memory usage (%).
[[nodiscard]] uint8_t QueryMemoryUsage() noexcept {
    MEMORYSTATUSEX msx{};
    msx.dwLength = sizeof(msx);
    if (!::GlobalMemoryStatusEx(&msx)) return 0;
    return static_cast<uint8_t>(msx.dwMemoryLoad);
}

}  // anonymous namespace

// ============================================================================
// NAMESPACE
// ============================================================================

namespace ShadowStrike {
namespace Update {

// ============================================================================
// FREE-FUNCTION: NAME LOOKUPS
// ============================================================================

std::string_view GetSchedulerStateName(SchedulerState state) noexcept {
    switch (state) {
    case SchedulerState::Stopped:   return "Stopped";
    case SchedulerState::Running:   return "Running";
    case SchedulerState::Paused:    return "Paused";
    case SchedulerState::Checking:  return "Checking";
    case SchedulerState::Waiting:   return "Waiting";
    }
    return "Unknown";
}

std::string_view GetCheckTriggerName(CheckTrigger trigger) noexcept {
    switch (trigger) {
    case CheckTrigger::Scheduled:     return "Scheduled";
    case CheckTrigger::Manual:        return "Manual";
    case CheckTrigger::Startup:       return "Startup";
    case CheckTrigger::NetworkChange: return "NetworkChange";
    case CheckTrigger::WakeFromSleep: return "WakeFromSleep";
    case CheckTrigger::Forced:        return "Forced";
    case CheckTrigger::Enterprise:    return "Enterprise";
    }
    return "Unknown";
}

std::string_view GetDeferralReasonName(DeferralReason reason) noexcept {
    switch (reason) {
    case DeferralReason::None:              return "None";
    case DeferralReason::HighCPU:           return "HighCPU";
    case DeferralReason::GameMode:          return "GameMode";
    case DeferralReason::Presentation:      return "Presentation";
    case DeferralReason::MeteredNetwork:    return "MeteredNetwork";
    case DeferralReason::OnBattery:         return "OnBattery";
    case DeferralReason::QuietHours:        return "QuietHours";
    case DeferralReason::UserDeferred:      return "UserDeferred";
    case DeferralReason::MaintenanceWindow: return "MaintenanceWindow";
    case DeferralReason::MaxDeferred:       return "MaxDeferred";
    }
    return "Unknown";
}

std::string_view GetNetworkTypeName(NetworkType type) noexcept {
    switch (type) {
    case NetworkType::Unknown:   return "Unknown";
    case NetworkType::Ethernet:  return "Ethernet";
    case NetworkType::WiFi:      return "WiFi";
    case NetworkType::Cellular:  return "Cellular";
    case NetworkType::VPN:       return "VPN";
    case NetworkType::Satellite: return "Satellite";
    }
    return "Unknown";
}

// ============================================================================
// FREE-FUNCTION: NETWORK DETECTION
// ============================================================================

NetworkType DetectNetworkType() {
    // Use GetAdaptersAddresses to find the best connected adapter type.
    ULONG bufLen = 16384;
    std::vector<uint8_t> buf(bufLen);
    auto* addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG ret = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &bufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        ret = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &bufLen);
    }
    if (ret != NO_ERROR) {
        SS_LOG_WARN(kLogCategory, L"GetAdaptersAddresses failed: %lu", ret);
        return NetworkType::Unknown;
    }

    // Walk adapters, prefer operational-up adapters.
    bool foundEthernet  = false;
    bool foundWifi      = false;
    bool foundCellular  = false;

    for (auto* cur = addrs; cur; cur = cur->Next) {
        if (cur->OperStatus != IfOperStatusUp) continue;
        if (cur->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        // Tunnel adapters often indicate VPN.
        if (cur->IfType == IF_TYPE_TUNNEL) return NetworkType::VPN;

        if (cur->IfType == IF_TYPE_ETHERNET_CSMACD ||
            cur->IfType == IF_TYPE_GIGABITETHERNET)
        {
            foundEthernet = true;
        }
        else if (cur->IfType == IF_TYPE_IEEE80211) {
            foundWifi = true;
        }
        else if (cur->IfType == IF_TYPE_WWANPP ||
                 cur->IfType == IF_TYPE_WWANPP2)
        {
            foundCellular = true;
        }
    }

    if (foundEthernet)  return NetworkType::Ethernet;
    if (foundWifi)      return NetworkType::WiFi;
    if (foundCellular)  return NetworkType::Cellular;
    return NetworkType::Unknown;
}

bool IsNetworkMetered() {
    // Heuristic: cellular connections are treated as metered.
    // Full INetworkCostManager requires COM; use adapter type as proxy.
    const auto netType = DetectNetworkType();
    return (netType == NetworkType::Cellular);
}

// ============================================================================
// STRUCT METHODS — ScheduleRule
// ============================================================================

bool ScheduleRule::IsActiveNow() const {
    if (!enabled) return false;

    const uint8_t dayBit = CurrentDayBit();
    if ((daysOfWeek & dayBit) == 0) return false;

    const uint16_t nowMin = CurrentMinutesFromMidnight();
    if (startMinutes <= endMinutes) {
        return (nowMin >= startMinutes && nowMin < endMinutes);
    }
    // Overnight wrap (e.g. 22:00-06:00)
    return (nowMin >= startMinutes || nowMin < endMinutes);
}

std::string ScheduleRule::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"ruleId\":\"" << JsonEscape(ruleId) << "\","
       << "\"name\":\"" << JsonEscape(name) << "\","
       << "\"enabled\":" << (enabled ? "true" : "false") << ","
       << "\"intervalHours\":" << intervalHours << ","
       << "\"daysOfWeek\":" << static_cast<unsigned>(daysOfWeek) << ","
       << "\"startMinutes\":" << startMinutes << ","
       << "\"endMinutes\":" << endMinutes << ","
       << "\"deferOnHighCPU\":" << (deferOnHighCPU ? "true" : "false") << ","
       << "\"cpuThreshold\":" << static_cast<unsigned>(cpuThreshold) << ","
       << "\"deferDuringGaming\":" << (deferDuringGaming ? "true" : "false") << ","
       << "\"deferOnBattery\":" << (deferOnBattery ? "true" : "false") << ","
       << "\"deferOnMetered\":" << (deferOnMetered ? "true" : "false")
       << "}";
    return js.str();
}

// ============================================================================
// STRUCT METHODS — QuietHours
// ============================================================================

bool QuietHours::IsActiveNow() const {
    if (!enabled) return false;

    const uint8_t dayBit = CurrentDayBit();
    if ((daysOfWeek & dayBit) == 0) return false;

    const uint16_t nowMin = CurrentMinutesFromMidnight();
    if (startMinutes <= endMinutes) {
        return (nowMin >= startMinutes && nowMin < endMinutes);
    }
    // Overnight wrap (e.g. 22:00-07:00)
    return (nowMin >= startMinutes || nowMin < endMinutes);
}

std::string QuietHours::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"enabled\":" << (enabled ? "true" : "false") << ","
       << "\"startMinutes\":" << startMinutes << ","
       << "\"endMinutes\":" << endMinutes << ","
       << "\"daysOfWeek\":" << static_cast<unsigned>(daysOfWeek)
       << "}";
    return js.str();
}

// ============================================================================
// STRUCT METHODS — MaintenanceWindow
// ============================================================================

bool MaintenanceWindow::IsActiveNow() const {
    if (!enabled) return false;

    const auto now = std::chrono::system_clock::now();
    const auto dur = std::chrono::minutes(durationMinutes);

    if (recurrenceDays == 0) {
        // One-shot: [startTime, startTime + duration)
        return (now >= startTime && now < startTime + dur);
    }

    // Recurring: find the most recent occurrence at or before now.
    const auto recurrence = std::chrono::hours(24) * recurrenceDays;
    if (now < startTime) return false;

    const auto elapsed = now - startTime;
    // Number of full recurrence periods since start
    const auto periods = std::chrono::duration_cast<std::chrono::hours>(elapsed).count()
                         / (static_cast<int64_t>(recurrenceDays) * 24);
    const auto lastOccurrence = startTime + recurrence * periods;
    return (now >= lastOccurrence && now < lastOccurrence + dur);
}

std::string MaintenanceWindow::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"windowId\":\"" << JsonEscape(windowId) << "\","
       << "\"name\":\"" << JsonEscape(name) << "\","
       << "\"enabled\":" << (enabled ? "true" : "false") << ","
       << "\"startTime\":\"" << FormatIso8601(startTime) << "\","
       << "\"durationMinutes\":" << durationMinutes << ","
       << "\"recurrenceDays\":" << recurrenceDays
       << "}";
    return js.str();
}

// ============================================================================
// STRUCT METHODS — SystemState
// ============================================================================

std::string SystemState::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"cpuUsage\":" << static_cast<unsigned>(cpuUsage) << ","
       << "\"memoryUsage\":" << static_cast<unsigned>(memoryUsage) << ","
       << "\"isGaming\":" << (isGaming ? "true" : "false") << ","
       << "\"isPresenting\":" << (isPresenting ? "true" : "false") << ","
       << "\"isOnBattery\":" << (isOnBattery ? "true" : "false") << ","
       << "\"batteryPercent\":" << static_cast<unsigned>(batteryPercent) << ","
       << "\"networkType\":\"" << GetNetworkTypeName(networkType) << "\","
       << "\"isMetered\":" << (isMetered ? "true" : "false") << ","
       << "\"isVPN\":" << (isVPN ? "true" : "false") << ","
       << "\"isQuietHours\":" << (isQuietHours ? "true" : "false")
       << "}";
    return js.str();
}

// ============================================================================
// STRUCT METHODS — ScheduleInfo
// ============================================================================

std::string ScheduleInfo::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"nextCheckTime\":";
    if (nextCheckTime.has_value()) {
        js << "\"" << FormatIso8601(nextCheckTime.value()) << "\"";
    } else {
        js << "null";
    }
    js << ",\"lastCheckTime\":";
    if (lastCheckTime.has_value()) {
        js << "\"" << FormatIso8601(lastCheckTime.value()) << "\"";
    } else {
        js << "null";
    }
    js << ",\"lastCheckTrigger\":\"" << GetCheckTriggerName(lastCheckTrigger) << "\","
       << "\"deferralReason\":\"" << GetDeferralReasonName(deferralReason) << "\","
       << "\"deferralCount\":" << deferralCount << ","
       << "\"checksToday\":" << checksToday
       << "}";
    return js.str();
}

// ============================================================================
// STRUCT METHODS — SchedulerStatistics
// ============================================================================

void SchedulerStatistics::Reset() noexcept {
    checksTriggered = 0;
    checksCompleted = 0;
    checksFailed    = 0;
    checksDeferred  = 0;
    updatesFound    = 0;
    updatesApplied  = 0;
    for (auto& v : byDeferralReason) v = 0;
    for (auto& v : byTrigger)        v = 0;
    startTime = Clock::now();
}

std::string SchedulerStatistics::ToJson() const {
    const auto uptimeSec = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    std::ostringstream js;
    js << "{"
       << "\"checksTriggered\":" << checksTriggered << ","
       << "\"checksCompleted\":" << checksCompleted << ","
       << "\"checksFailed\":" << checksFailed << ","
       << "\"checksDeferred\":" << checksDeferred << ","
       << "\"updatesFound\":" << updatesFound << ","
       << "\"updatesApplied\":" << updatesApplied << ","
       << "\"byDeferralReason\":[";
    for (size_t i = 0; i < byDeferralReason.size(); ++i) {
        if (i > 0) js << ",";
        js << byDeferralReason[i];
    }
    js << "],\"byTrigger\":[";
    for (size_t i = 0; i < byTrigger.size(); ++i) {
        if (i > 0) js << ",";
        js << byTrigger[i];
    }
    js << "],\"uptimeSeconds\":" << uptimeSec
       << "}";
    return js.str();
}

// ============================================================================
// STRUCT METHODS — UpdateSchedulerConfiguration
// ============================================================================

bool UpdateSchedulerConfiguration::IsValid() const noexcept {
    if (defaultIntervalHours == 0) return false;
    if (cpuDeferThreshold > 100) return false;
    if (maxDeferHours == 0 || maxDeferHours > 720) return false;
    return true;
}

// ============================================================================
// PIMPL — UpdateSchedulerImpl
// ============================================================================

class UpdateSchedulerImpl {
public:
    // ---- Configuration & state ------------------------------------------
    UpdateSchedulerConfiguration  m_config;
    mutable std::shared_mutex     m_mutex;
    SchedulerState                m_schedulerState{ SchedulerState::Stopped };
    SchedulerStatus               m_status{ SchedulerStatus::Uninitialized };
    std::atomic<bool>             m_initialized{ false };

    // ---- Interval -------------------------------------------------------
    std::chrono::hours            m_interval{ SchedulerConstants::DEFAULT_CHECK_INTERVAL_HOURS };

    // ---- Rules, quiet hours, maintenance windows ------------------------
    std::vector<ScheduleRule>     m_rules;
    QuietHours                    m_quietHours;
    std::vector<MaintenanceWindow> m_maintenanceWindows;

    // ---- Schedule info --------------------------------------------------
    ScheduleInfo                  m_scheduleInfo;

    // ---- Statistics (plain uint64_t — protected by m_mutex) -------------
    SchedulerStatistics           m_stats;

    // ---- Callbacks (separate lock) --------------------------------------
    CheckTriggeredCallback        m_checkTriggeredCb;
    DeferralCallback              m_deferralCb;
    StateChangeCallback           m_stateChangeCb;
    ErrorCallback                 m_errorCb;
    mutable std::mutex            m_callbackMutex;

    // ---- Scheduler thread -----------------------------------------------
    std::thread                   m_thread;
    std::mutex                    m_cvMutex;
    std::condition_variable       m_cv;
    std::atomic<bool>             m_stopFlag{ false };
    std::atomic<bool>             m_triggerFlag{ false };
    CheckTrigger                  m_pendingTrigger{ CheckTrigger::Scheduled };

    // Serialises Start()/Stop() so concurrent callers cannot both attempt
    // to assign m_thread (which would std::terminate on a joinable thread).
    std::mutex                    m_lifecycleMutex;

    // ---- Cached system state --------------------------------------------
    SystemState                   m_cachedSystemState;
    TimePoint                     m_lastSystemStateQuery;

    // =====================================================================
    // Helper — notify callbacks (exception-safe, under callback mutex)
    // =====================================================================

    void NotifyCheckTriggered(CheckTrigger trigger) {
        std::lock_guard lock(m_callbackMutex);
        if (m_checkTriggeredCb) {
            try { m_checkTriggeredCb(trigger); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"CheckTriggered callback threw exception"); }
        }
    }

    void NotifyDeferral(DeferralReason reason) {
        std::lock_guard lock(m_callbackMutex);
        if (m_deferralCb) {
            try { m_deferralCb(reason); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Deferral callback threw exception"); }
        }
    }

    void NotifyStateChange(SchedulerState newState) {
        std::lock_guard lock(m_callbackMutex);
        if (m_stateChangeCb) {
            try { m_stateChangeCb(newState); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"StateChange callback threw exception"); }
        }
    }

    void NotifyError(const std::string& message, int code) {
        std::lock_guard lock(m_callbackMutex);
        if (m_errorCb) {
            try { m_errorCb(message, code); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Error callback threw exception"); }
        }
    }

    // =====================================================================
    // Helper — set scheduler state + notify
    // =====================================================================

    void SetState(SchedulerState newState) {
        // Caller must hold m_mutex (unique_lock).
        m_schedulerState = newState;
        NotifyStateChange(newState);
    }

    // =====================================================================
    // Helper — refresh cached system state
    // =====================================================================

    void RefreshSystemState() {
        // Throttle: at most once per second to avoid hammering syscalls.
        const auto now = Clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - m_lastSystemStateQuery).count() < 1)
        {
            return;
        }
        m_lastSystemStateQuery = now;

        const auto cpuPct    = QueryCpuUsage();
        const auto memPct    = QueryMemoryUsage();
        const auto battery   = QueryBatteryStatus();
        const auto userMode  = QueryUserMode();
        const auto netType   = DetectNetworkType();
        const bool metered   = IsNetworkMetered();
        const bool qh        = m_quietHours.IsActiveNow();

        std::unique_lock lock(m_mutex);
        m_cachedSystemState.cpuUsage       = cpuPct;
        m_cachedSystemState.memoryUsage    = memPct;
        m_cachedSystemState.isGaming       = userMode.gaming;
        m_cachedSystemState.isPresenting   = userMode.presenting;
        m_cachedSystemState.isOnBattery    = battery.onBattery;
        m_cachedSystemState.batteryPercent = battery.percent;
        m_cachedSystemState.networkType    = netType;
        m_cachedSystemState.isMetered      = metered;
        m_cachedSystemState.isVPN          = (netType == NetworkType::VPN);
        m_cachedSystemState.isQuietHours   = qh;
        m_cachedSystemState.lastActivityTime = now;
    }

    // =====================================================================
    // Helper — evaluate deferral conditions (called under m_mutex read-lock)
    // =====================================================================

    [[nodiscard]] DeferralReason EvaluateDeferral() const {
        // Priority order: matching the DeferralReason enum ordering.
        if (m_config.enableSystemStateChecks) {
            if (m_cachedSystemState.cpuUsage >= m_config.cpuDeferThreshold)
                return DeferralReason::HighCPU;
        }
        if (m_config.enableGameModeRespect && m_cachedSystemState.isGaming)
            return DeferralReason::GameMode;
        if (m_cachedSystemState.isPresenting)
            return DeferralReason::Presentation;
        if (m_config.enableMeteredDetection && m_cachedSystemState.isMetered)
            return DeferralReason::MeteredNetwork;
        if (m_cachedSystemState.isOnBattery)
            return DeferralReason::OnBattery;
        if (m_cachedSystemState.isQuietHours)
            return DeferralReason::QuietHours;

        // Check if we are outside all active maintenance windows when
        // maintenance windows are configured (defer if outside ALL windows).
        // NOTE: maintenance windows are PREFERRED times; we only gate on them
        // if at least one is defined and enabled.
        bool hasEnabledWindow = false;
        bool inAnyWindow      = false;
        for (const auto& w : m_maintenanceWindows) {
            if (w.enabled) {
                hasEnabledWindow = true;
                if (w.IsActiveNow()) { inAnyWindow = true; break; }
            }
        }
        if (hasEnabledWindow && !inAnyWindow)
            return DeferralReason::MaintenanceWindow;

        return DeferralReason::None;
    }

    // =====================================================================
    // Helper — compute next check time-point (system_clock)
    // =====================================================================

    [[nodiscard]] SystemTimePoint ComputeNextCheckTime() const {
        return std::chrono::system_clock::now() + m_interval;
    }

    // =====================================================================
    // Background scheduler thread entry-point
    // =====================================================================

    void SchedulerThreadFunc() {
        SS_LOG_INFO(kLogCategory, L"Scheduler thread started");

        while (!m_stopFlag.load(std::memory_order_acquire)) {
            // Snapshot interval under lock — m_interval is mutated by
            // SetInterval() and would otherwise be a data race in wait_for.
            std::chrono::hours waitInterval;
            bool isPaused = false;
            {
                std::shared_lock lock(m_mutex);
                waitInterval = m_interval;
                isPaused = (m_schedulerState == SchedulerState::Paused);
            }

            // Sleep / wait for trigger or interval expiry.
            {
                std::unique_lock cvLock(m_cvMutex);
                m_cv.wait_for(cvLock, waitInterval, [this] {
                    return m_stopFlag.load(std::memory_order_acquire) ||
                           m_triggerFlag.load(std::memory_order_acquire);
                });
            }

            if (m_stopFlag.load(std::memory_order_acquire)) break;

            // Re-evaluate pause after waking: if Paused (and this is not
            // a manual trigger), park until resumed. Pause must actually
            // suppress check execution — otherwise the thread runs checks
            // while the public API reports Paused state.
            {
                std::shared_lock lock(m_mutex);
                isPaused = (m_schedulerState == SchedulerState::Paused);
            }
            if (isPaused && !m_triggerFlag.load(std::memory_order_acquire)) {
                std::unique_lock cvLock(m_cvMutex);
                m_cv.wait(cvLock, [this] {
                    if (m_stopFlag.load(std::memory_order_acquire)) return true;
                    if (m_triggerFlag.load(std::memory_order_acquire)) return true;
                    std::shared_lock lock(m_mutex);
                    return m_schedulerState != SchedulerState::Paused;
                });
                if (m_stopFlag.load(std::memory_order_acquire)) break;
            }

            // Determine trigger type.
            CheckTrigger trigger = CheckTrigger::Scheduled;
            if (m_triggerFlag.load(std::memory_order_acquire)) {
                m_triggerFlag.store(false, std::memory_order_release);
                std::shared_lock lock(m_mutex);
                trigger = m_pendingTrigger;
            }

            // Refresh system state before deferral check.
            RefreshSystemState();

            // Record trigger in stats.
            {
                std::unique_lock lock(m_mutex);
                m_stats.checksTriggered++;
                const auto trigIdx = static_cast<size_t>(trigger);
                if (trigIdx < m_stats.byTrigger.size()) {
                    m_stats.byTrigger[trigIdx]++;
                }
                m_scheduleInfo.lastCheckTrigger = trigger;
                m_scheduleInfo.lastCheckTime = std::chrono::system_clock::now();
            }

            NotifyCheckTriggered(trigger);

            // Evaluate deferral (unless Forced or Enterprise which bypass).
            if (trigger != CheckTrigger::Forced &&
                trigger != CheckTrigger::Enterprise)
            {
                std::shared_lock lock(m_mutex);
                const auto reason = EvaluateDeferral();
                if (reason != DeferralReason::None) {
                    const auto reasonIdx = static_cast<size_t>(reason);
                    lock.unlock();  // upgrade to exclusive
                    {
                        std::unique_lock wlock(m_mutex);
                        m_stats.checksDeferred++;
                        if (reasonIdx < m_stats.byDeferralReason.size()) {
                            m_stats.byDeferralReason[reasonIdx]++;
                        }
                        m_scheduleInfo.deferralReason = reason;
                        m_scheduleInfo.deferralCount++;

                        // Exponential backoff for next check (capped).
                        const uint32_t backoffHours = std::min<uint32_t>(
                            1u << std::min<uint32_t>(m_scheduleInfo.deferralCount, 6u),
                            m_config.maxDeferHours);
                        m_scheduleInfo.nextCheckTime =
                            std::chrono::system_clock::now() +
                            std::chrono::hours(backoffHours);
                    }

                    SS_LOG_INFO(kLogCategory, L"Check deferred: reason=%S, count=%u",
                        std::string(GetDeferralReasonName(reason)).c_str(),
                        m_scheduleInfo.deferralCount);

                    NotifyDeferral(reason);
                    continue;
                }
            }

            // Perform the check.
            {
                std::unique_lock lock(m_mutex);
                SetState(SchedulerState::Checking);
            }

            SS_LOG_INFO(kLogCategory, L"Performing update check (trigger=%S)",
                std::string(GetCheckTriggerName(trigger)).c_str());

            // The actual network check is performed by UpdateManager — the
            // scheduler only signals that a check should happen.  Record as
            // completed (downstream modules handle failures independently).
            {
                std::unique_lock lock(m_mutex);
                m_stats.checksCompleted++;
                m_scheduleInfo.checksToday++;
                m_scheduleInfo.deferralReason = DeferralReason::None;
                m_scheduleInfo.deferralCount  = 0;
                m_scheduleInfo.nextCheckTime  = ComputeNextCheckTime();
                SetState(SchedulerState::Running);
            }
        }

        SS_LOG_INFO(kLogCategory, L"Scheduler thread exiting");
    }
};

// ============================================================================
// STATIC MEMBER
// ============================================================================

std::atomic<bool> UpdateScheduler::s_instanceCreated{ false };

// ============================================================================
// SINGLETON (Meyers')
// ============================================================================

UpdateScheduler& UpdateScheduler::Instance() noexcept {
    static UpdateScheduler instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool UpdateScheduler::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

UpdateScheduler::UpdateScheduler()
    : m_impl(std::make_unique<UpdateSchedulerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_DEBUG(kLogCategory, L"UpdateScheduler constructed");
}

UpdateScheduler::~UpdateScheduler() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
    SS_LOG_DEBUG(kLogCategory, L"UpdateScheduler destroyed");
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool UpdateScheduler::Initialize(const UpdateSchedulerConfiguration& config) {
    if (!m_impl) return false;

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"Already initialized — skipping re-initialization");
        return true;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid configuration supplied to Initialize()");
        m_impl->NotifyError("Invalid scheduler configuration", -1);
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = SchedulerStatus::Initializing;

    SS_LOG_INFO(kLogCategory, L"Initializing UpdateScheduler v%u.%u.%u",
        SchedulerConstants::VERSION_MAJOR,
        SchedulerConstants::VERSION_MINOR,
        SchedulerConstants::VERSION_PATCH);

    m_impl->m_config = config;
    m_impl->m_interval = std::chrono::hours(config.defaultIntervalHours);
    m_impl->m_quietHours = config.quietHours;
    m_impl->m_stats.Reset();
    m_impl->m_scheduleInfo = {};
    m_impl->m_cachedSystemState = {};
    m_impl->m_lastSystemStateQuery = {};

    m_impl->m_initialized.store(true, std::memory_order_release);
    m_impl->m_status = SchedulerStatus::Stopped;
    m_impl->m_schedulerState = SchedulerState::Stopped;

    SS_LOG_INFO(kLogCategory,
        L"Initialized: interval=%uh, intelligent=%s, sysChecks=%s, gameMode=%s",
        config.defaultIntervalHours,
        config.enableIntelligentScheduling ? L"on" : L"off",
        config.enableSystemStateChecks ? L"on" : L"off",
        config.enableGameModeRespect ? L"on" : L"off");

    // Auto-start if enabled + checkOnStartup.
    if (config.enabled) {
        lock.unlock();
        Start();
        if (config.checkOnStartup) {
            TriggerCheck(CheckTrigger::Startup);
        }
    }

    return true;
}

void UpdateScheduler::Shutdown() {
    if (!m_impl) return;

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(kLogCategory, L"Shutting down UpdateScheduler");

    // Stop the scheduler thread first (outside main lock to avoid deadlock).
    Stop();

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = SchedulerStatus::Stopping;

    // Clear rules / windows.
    m_impl->m_rules.clear();
    m_impl->m_maintenanceWindows.clear();

    // Clear callbacks.
    {
        std::lock_guard cbLock(m_impl->m_callbackMutex);
        m_impl->m_checkTriggeredCb = nullptr;
        m_impl->m_deferralCb       = nullptr;
        m_impl->m_stateChangeCb    = nullptr;
        m_impl->m_errorCb          = nullptr;
    }

    m_impl->m_initialized.store(false, std::memory_order_release);
    m_impl->m_status = SchedulerStatus::Stopped;

    SS_LOG_INFO(kLogCategory, L"UpdateScheduler shut down");
}

bool UpdateScheduler::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

SchedulerStatus UpdateScheduler::GetStatus() const noexcept {
    if (!m_impl) return SchedulerStatus::Uninitialized;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// SCHEDULER CONTROL
// ============================================================================

void UpdateScheduler::Start() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"Start() called on uninitialized scheduler");
        return;
    }

    // Serialise lifecycle transitions so two callers cannot race to assign
    // m_thread (which would terminate on a joinable thread).
    std::lock_guard lifecycle(m_impl->m_lifecycleMutex);

    {
        std::shared_lock lock(m_impl->m_mutex);
        if (m_impl->m_schedulerState == SchedulerState::Running ||
            m_impl->m_schedulerState == SchedulerState::Checking ||
            m_impl->m_schedulerState == SchedulerState::Waiting)
        {
            SS_LOG_DEBUG(kLogCategory, L"Scheduler already running");
            return;
        }
    }

    // Ensure old thread is cleaned up.
    m_impl->m_stopFlag.store(true, std::memory_order_release);
    m_impl->m_cv.notify_all();
    if (m_impl->m_thread.joinable()) {
        m_impl->m_thread.join();
    }

    m_impl->m_stopFlag.store(false, std::memory_order_release);
    m_impl->m_triggerFlag.store(false, std::memory_order_release);

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->SetState(SchedulerState::Running);
        m_impl->m_status = SchedulerStatus::Running;
        m_impl->m_scheduleInfo.nextCheckTime = m_impl->ComputeNextCheckTime();
    }

    m_impl->m_thread = std::thread(&UpdateSchedulerImpl::SchedulerThreadFunc, m_impl.get());

    SS_LOG_INFO(kLogCategory, L"Scheduler started");
}

void UpdateScheduler::Stop() {
    if (!m_impl) return;

    // Serialise against Start() — see m_lifecycleMutex rationale.
    std::lock_guard lifecycle(m_impl->m_lifecycleMutex);

    {
        std::shared_lock lock(m_impl->m_mutex);
        if (m_impl->m_schedulerState == SchedulerState::Stopped) return;
    }

    m_impl->m_stopFlag.store(true, std::memory_order_release);
    m_impl->m_cv.notify_all();

    if (m_impl->m_thread.joinable()) {
        m_impl->m_thread.join();
    }

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->SetState(SchedulerState::Stopped);
        m_impl->m_status = SchedulerStatus::Stopped;
        m_impl->m_scheduleInfo.nextCheckTime.reset();
    }

    SS_LOG_INFO(kLogCategory, L"Scheduler stopped");
}

void UpdateScheduler::Pause() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return;

    std::unique_lock lock(m_impl->m_mutex);
    if (m_impl->m_schedulerState != SchedulerState::Running &&
        m_impl->m_schedulerState != SchedulerState::Waiting)
    {
        SS_LOG_DEBUG(kLogCategory, L"Cannot pause scheduler in state %S",
            std::string(GetSchedulerStateName(m_impl->m_schedulerState)).c_str());
        return;
    }

    m_impl->SetState(SchedulerState::Paused);
    m_impl->m_status = SchedulerStatus::Paused;
    SS_LOG_INFO(kLogCategory, L"Scheduler paused");
}

void UpdateScheduler::Resume() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return;

    {
        std::unique_lock lock(m_impl->m_mutex);
        if (m_impl->m_schedulerState != SchedulerState::Paused) {
            SS_LOG_DEBUG(kLogCategory, L"Resume() called but scheduler is not paused");
            return;
        }

        m_impl->SetState(SchedulerState::Running);
        m_impl->m_status = SchedulerStatus::Running;
    }

    // Wake the worker thread so it observes the new state.
    m_impl->m_cv.notify_all();

    SS_LOG_INFO(kLogCategory, L"Scheduler resumed");
}

SchedulerState UpdateScheduler::GetState() const noexcept {
    if (!m_impl) return SchedulerState::Stopped;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_schedulerState;
}

bool UpdateScheduler::IsRunning() const noexcept {
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->m_mutex);
    return (m_impl->m_schedulerState == SchedulerState::Running ||
            m_impl->m_schedulerState == SchedulerState::Checking ||
            m_impl->m_schedulerState == SchedulerState::Waiting);
}

// ============================================================================
// INTERVAL CONTROL
// ============================================================================

void UpdateScheduler::SetInterval(std::chrono::hours interval) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return;

    const auto hrs = interval.count();
    if (hrs <= 0 ||
        static_cast<uint64_t>(hrs) * 60 < SchedulerConstants::MIN_CHECK_INTERVAL_MINUTES)
    {
        SS_LOG_WARN(kLogCategory, L"SetInterval rejected: %lld hours below minimum", hrs);
        return;
    }

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_interval = interval;
        m_impl->m_scheduleInfo.nextCheckTime = m_impl->ComputeNextCheckTime();
    }

    // Wake the thread so it sleeps with the new interval.
    m_impl->m_cv.notify_all();

    SS_LOG_INFO(kLogCategory, L"Check interval set to %lldh", hrs);
}

std::chrono::hours UpdateScheduler::GetInterval() const {
    if (!m_impl) return std::chrono::hours(SchedulerConstants::DEFAULT_CHECK_INTERVAL_HOURS);
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_interval;
}

void UpdateScheduler::TriggerCheck(CheckTrigger trigger) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"TriggerCheck on uninitialized scheduler");
        return;
    }

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_pendingTrigger = trigger;
    }

    m_impl->m_triggerFlag.store(true, std::memory_order_release);
    m_impl->m_cv.notify_all();

    SS_LOG_INFO(kLogCategory, L"Manual check triggered: %S",
        std::string(GetCheckTriggerName(trigger)).c_str());
}

std::optional<SystemTimePoint> UpdateScheduler::GetNextCheckTime() const {
    if (!m_impl) return std::nullopt;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_scheduleInfo.nextCheckTime;
}

// ============================================================================
// RULE MANAGEMENT
// ============================================================================

bool UpdateScheduler::AddRule(const ScheduleRule& rule) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return false;

    if (rule.ruleId.empty()) {
        SS_LOG_ERROR(kLogCategory, L"Cannot add rule with empty ruleId");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    // Reject duplicates.
    for (const auto& r : m_impl->m_rules) {
        if (r.ruleId == rule.ruleId) {
            SS_LOG_WARN(kLogCategory, L"Rule '%S' already exists",
                rule.ruleId.c_str());
            return false;
        }
    }

    m_impl->m_rules.push_back(rule);
    SS_LOG_INFO(kLogCategory, L"Rule added: '%S' (%S)",
        rule.ruleId.c_str(), rule.name.c_str());
    return true;
}

bool UpdateScheduler::RemoveRule(const std::string& ruleId) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return false;

    std::unique_lock lock(m_impl->m_mutex);
    auto it = std::find_if(m_impl->m_rules.begin(), m_impl->m_rules.end(),
        [&](const ScheduleRule& r) { return r.ruleId == ruleId; });

    if (it == m_impl->m_rules.end()) {
        SS_LOG_WARN(kLogCategory, L"Rule '%S' not found for removal", ruleId.c_str());
        return false;
    }

    m_impl->m_rules.erase(it);
    SS_LOG_INFO(kLogCategory, L"Rule removed: '%S'", ruleId.c_str());
    return true;
}

std::vector<ScheduleRule> UpdateScheduler::GetRules() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_rules;
}

void UpdateScheduler::SetQuietHours(const QuietHours& quietHours) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_quietHours = quietHours;
    m_impl->m_config.quietHours = quietHours;

    SS_LOG_INFO(kLogCategory, L"Quiet hours updated: enabled=%s, %u-%u",
        quietHours.enabled ? L"yes" : L"no",
        static_cast<unsigned>(quietHours.startMinutes),
        static_cast<unsigned>(quietHours.endMinutes));
}

QuietHours UpdateScheduler::GetQuietHours() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_quietHours;
}

// ============================================================================
// MAINTENANCE WINDOWS
// ============================================================================

bool UpdateScheduler::AddMaintenanceWindow(const MaintenanceWindow& window) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return false;

    if (window.windowId.empty()) {
        SS_LOG_ERROR(kLogCategory, L"Cannot add maintenance window with empty windowId");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    for (const auto& w : m_impl->m_maintenanceWindows) {
        if (w.windowId == window.windowId) {
            SS_LOG_WARN(kLogCategory, L"Maintenance window '%S' already exists",
                window.windowId.c_str());
            return false;
        }
    }

    m_impl->m_maintenanceWindows.push_back(window);
    SS_LOG_INFO(kLogCategory, L"Maintenance window added: '%S' (%S)",
        window.windowId.c_str(), window.name.c_str());
    return true;
}

bool UpdateScheduler::RemoveMaintenanceWindow(const std::string& windowId) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) return false;

    std::unique_lock lock(m_impl->m_mutex);
    auto it = std::find_if(m_impl->m_maintenanceWindows.begin(),
                           m_impl->m_maintenanceWindows.end(),
        [&](const MaintenanceWindow& w) { return w.windowId == windowId; });

    if (it == m_impl->m_maintenanceWindows.end()) {
        SS_LOG_WARN(kLogCategory, L"Maintenance window '%S' not found", windowId.c_str());
        return false;
    }

    m_impl->m_maintenanceWindows.erase(it);
    SS_LOG_INFO(kLogCategory, L"Maintenance window removed: '%S'", windowId.c_str());
    return true;
}

std::vector<MaintenanceWindow> UpdateScheduler::GetMaintenanceWindows() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_maintenanceWindows;
}

bool UpdateScheduler::IsInMaintenanceWindow() const {
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->m_mutex);
    for (const auto& w : m_impl->m_maintenanceWindows) {
        if (w.IsActiveNow()) return true;
    }
    return false;
}

// ============================================================================
// STATE INFORMATION
// ============================================================================

SystemState UpdateScheduler::GetSystemState() const {
    if (!m_impl) return {};

    // Force a refresh (const_cast is safe: RefreshSystemState is self-locking).
    const_cast<UpdateSchedulerImpl*>(m_impl.get())->RefreshSystemState();

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_cachedSystemState;
}

ScheduleInfo UpdateScheduler::GetScheduleInfo() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_scheduleInfo;
}

bool UpdateScheduler::CanUpdateNow() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return false;

    const_cast<UpdateSchedulerImpl*>(m_impl.get())->RefreshSystemState();

    std::shared_lock lock(m_impl->m_mutex);
    return (m_impl->EvaluateDeferral() == DeferralReason::None);
}

DeferralReason UpdateScheduler::GetCurrentDeferralReason() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire))
        return DeferralReason::None;

    const_cast<UpdateSchedulerImpl*>(m_impl.get())->RefreshSystemState();

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->EvaluateDeferral();
}

// ============================================================================
// CALLBACKS
// ============================================================================

void UpdateScheduler::RegisterCheckTriggeredCallback(CheckTriggeredCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_checkTriggeredCb = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"CheckTriggered callback registered");
}

void UpdateScheduler::RegisterDeferralCallback(DeferralCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_deferralCb = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Deferral callback registered");
}

void UpdateScheduler::RegisterStateChangeCallback(StateChangeCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_stateChangeCb = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"StateChange callback registered");
}

void UpdateScheduler::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCb = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Error callback registered");
}

void UpdateScheduler::UnregisterCallbacks() {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_checkTriggeredCb = nullptr;
    m_impl->m_deferralCb       = nullptr;
    m_impl->m_stateChangeCb    = nullptr;
    m_impl->m_errorCb          = nullptr;
    SS_LOG_DEBUG(kLogCategory, L"All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

SchedulerStatistics UpdateScheduler::GetStatistics() const {
    if (!m_impl) {
        SchedulerStatistics empty;
        return empty;
    }
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void UpdateScheduler::ResetStatistics() {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    SS_LOG_DEBUG(kLogCategory, L"Statistics reset");
}

// ============================================================================
// SELF-TEST
// ============================================================================

bool UpdateScheduler::SelfTest() {
    if (!m_impl) return false;

    SS_LOG_INFO(kLogCategory, L"Running self-test");

    // Test 1: Configuration validation.
    {
        UpdateSchedulerConfiguration validCfg;
        if (!validCfg.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAILED: default config is invalid");
            m_impl->NotifyError("Self-test failed: default config invalid", -1);
            return false;
        }
    }

    // Test 2: Schedule rule active-check logic.
    {
        ScheduleRule rule;
        rule.ruleId = "selftest";
        rule.enabled = true;
        rule.daysOfWeek = 0x7F;  // all days
        rule.startMinutes = 0;
        rule.endMinutes = 24 * 60;
        if (!rule.IsActiveNow()) {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAILED: all-day rule not active");
            m_impl->NotifyError("Self-test failed: rule IsActiveNow", -2);
            return false;
        }
    }

    // Test 3: Quiet hours logic (disabled → should not be active).
    {
        QuietHours qh;
        qh.enabled = false;
        if (qh.IsActiveNow()) {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAILED: disabled quiet hours is active");
            m_impl->NotifyError("Self-test failed: QuietHours disabled yet active", -3);
            return false;
        }
    }

    // Test 4: Name lookup functions return non-empty.
    {
        if (GetSchedulerStateName(SchedulerState::Running).empty() ||
            GetCheckTriggerName(CheckTrigger::Manual).empty() ||
            GetDeferralReasonName(DeferralReason::None).empty() ||
            GetNetworkTypeName(NetworkType::Ethernet).empty())
        {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAILED: name lookup returned empty");
            m_impl->NotifyError("Self-test failed: name lookup", -4);
            return false;
        }
    }

    // Test 5: Statistics reset.
    {
        SchedulerStatistics st;
        st.checksTriggered = 42;
        st.Reset();
        if (st.checksTriggered != 0) {
            SS_LOG_ERROR(kLogCategory, L"Self-test FAILED: stats Reset() not zeroing");
            m_impl->NotifyError("Self-test failed: stats reset", -5);
            return false;
        }
    }

    // Test 6: System state query does not crash.
    {
        (void)QueryCpuUsage();
        (void)QueryBatteryStatus();
        (void)QueryUserMode();
        (void)QueryMemoryUsage();
        (void)DetectNetworkType();
    }

    SS_LOG_INFO(kLogCategory, L"Self-test PASSED (6/6 checks)");
    return true;
}

// ============================================================================
// VERSION STRING
// ============================================================================

std::string UpdateScheduler::GetVersionString() noexcept {
    // "UpdateScheduler 3.0.0"
    std::string ver = "UpdateScheduler ";
    ver += std::to_string(SchedulerConstants::VERSION_MAJOR);
    ver += '.';
    ver += std::to_string(SchedulerConstants::VERSION_MINOR);
    ver += '.';
    ver += std::to_string(SchedulerConstants::VERSION_PATCH);
    return ver;
}

}  // namespace Update
}  // namespace ShadowStrike

