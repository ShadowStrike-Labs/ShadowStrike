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
#include "NotificationManager.hpp"

#include <algorithm>
#include <deque>
#include <thread>
#include <condition_variable>
#include <cstdio>
#include <ctime>
#include <shellapi.h>
#include <strsafe.h>
#include <Psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "Shell32.lib")

namespace ShadowStrike {
namespace Communication {

using Utils::StringUtils::ToWide;
using Utils::StringUtils::ToNarrow;

// ============================================================================
// HELPERS
// ============================================================================

static std::string GenerateNotificationId() {
    static std::atomic<uint64_t> s_counter{0};
    const uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "NTF-%llX-%04llX",
                  static_cast<unsigned long long>(ms),
                  static_cast<unsigned long long>(seq & 0xFFFF));
    return buf;
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned>(c));
                    out += hex;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

static std::string SystemTimeToIso8601(SystemTimePoint tp) {
    const auto tt = std::chrono::system_clock::to_time_t(tp);
    struct tm tmBuf{};
    gmtime_s(&tmBuf, &tt);
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tmBuf.tm_year + 1900, tmBuf.tm_mon + 1, tmBuf.tm_mday,
                  tmBuf.tm_hour, tmBuf.tm_min, tmBuf.tm_sec);
    return buf;
}

// ============================================================================
// GAME MODE / MEETING DETECTION
// ============================================================================

static bool CheckForFullscreenApp() {
    HWND fg = GetForegroundWindow();
    if (!fg) return false;

    RECT windowRect{};
    if (!GetWindowRect(fg, &windowRect)) return false;

    HMONITOR hMon = MonitorFromWindow(fg, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monInfo{};
    monInfo.cbSize = sizeof(monInfo);
    if (!GetMonitorInfoW(hMon, &monInfo)) return false;

    return (windowRect.left <= monInfo.rcMonitor.left &&
            windowRect.top <= monInfo.rcMonitor.top &&
            windowRect.right >= monInfo.rcMonitor.right &&
            windowRect.bottom >= monInfo.rcMonitor.bottom);
}

bool IsGameModeActive() {
    if (!CheckForFullscreenApp()) return false;

    HWND fg = GetForegroundWindow();
    if (!fg) return false;

    DWORD pid = 0;
    GetWindowThreadProcessId(fg, &pid);
    if (pid == 0) return false;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    wchar_t exePath[MAX_PATH]{};
    DWORD exePathLen = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(hProc, 0, exePath, &exePathLen);
    CloseHandle(hProc);

    if (!ok || exePathLen == 0) return false;

    // Heuristic: check if the executable is a known non-game (shell, desktop, etc.)
    std::wstring_view exe(exePath, exePathLen);
    auto filename = fs::path(exe).filename().wstring();
    std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);

    // Filter out OS processes that may be fullscreen (explorer, screensaver, etc.)
    static constexpr std::wstring_view kIgnored[] = {
        L"explorer.exe", L"dwm.exe", L"logonui.exe",
        L"shellexperiencehost.exe", L"searchui.exe",
        L"applicationframehost.exe", L"systemsettings.exe"
    };
    for (auto& ign : kIgnored) {
        if (filename == ign) return false;
    }

    return true;
}

bool IsInMeeting() {
    // Detect conferencing apps using audio/video
    static constexpr std::wstring_view kMeetingApps[] = {
        L"Teams.exe", L"ms-teams.exe", L"Zoom.exe",
        L"webex.exe", L"CiscoCollabHost.exe",
        L"slack.exe", L"Discord.exe",
        L"skype.exe", L"lync.exe",
        L"gotomeeting.exe", L"g2mcomm.exe"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool found = false;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            std::wstring_view procName(pe.szExeFile);
            for (auto& app : kMeetingApps) {
                if (_wcsicmp(procName.data(), app.data()) == 0) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return found;
}

// ============================================================================
// WINDOWS FOCUS ASSIST DETECTION
// ============================================================================

// Undocumented — WNF state for Focus Assist
// WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED
using PNTQUERYWNFSTATEDATA = NTSTATUS(NTAPI*)(
    const ULONG64* StateName,
    const void* TypeId,
    const void* ExplicitScope,
    PULONG ChangeStamp,
    PVOID Buffer,
    PULONG BufferSize);

static int GetFocusAssistStatus() {
    static PNTQUERYWNFSTATEDATA pNtQueryWnfStateData = nullptr;
    static std::once_flag s_once;
    std::call_once(s_once, [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            pNtQueryWnfStateData = reinterpret_cast<PNTQUERYWNFSTATEDATA>(
                GetProcAddress(ntdll, "NtQueryWnfStateData"));
        }
    });

    if (!pNtQueryWnfStateData) return 0;

    // WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED
    static constexpr ULONG64 kWnfShellQuietHoursActiveProfile = 0xD83063EA3BF1C75;

    ULONG changeStamp = 0;
    DWORD data = 0;
    ULONG dataSize = sizeof(data);

    NTSTATUS status = pNtQueryWnfStateData(
        &kWnfShellQuietHoursActiveProfile,
        nullptr, nullptr, &changeStamp, &data, &dataSize);

    if (status != 0) return 0;

    // 0 = off, 1 = priority only, 2 = alarms only
    return static_cast<int>(data);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class NotificationManagerImpl {
public:
    NotificationManagerImpl() = default;
    ~NotificationManagerImpl() { Shutdown(); }

    // Lifecycle
    bool Initialize(const NotificationConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const NotificationConfiguration& config);
    NotificationConfiguration GetConfiguration() const;

    // Notification operations
    void ShowSimple(const std::wstring& title, const std::wstring& message,
                    NotificationLevel level);
    std::string ShowFull(const Notification& notification);
    void ShowThreatAlertSimple(const std::wstring& threatName, const std::wstring& filePath);
    std::string ShowThreatAlertFull(const ThreatNotification& threat);
    bool Update(const Notification& notification);
    bool Remove(const std::string& notificationId);
    bool RemoveByTag(const std::string& tag);
    void ClearAll();

    // Quiet mode
    void EnableQuietMode(QuietModeState state);
    void DisableQuietMode();
    bool IsQuietModeActive() const noexcept;
    QuietModeState GetQuietModeState() const noexcept;
    void SetQuietHoursSchedule(const QuietHoursSchedule& schedule);

    // History
    std::optional<Notification> GetNotification(const std::string& notificationId);
    std::vector<Notification> GetRecentNotifications(size_t limit);
    std::vector<Notification> GetNotificationsByCategory(NotificationCategory category, size_t limit);
    void ClearHistory();

    // Preferences
    void SetPreferences(const NotificationPreferences& prefs);
    NotificationPreferences GetPreferences() const;
    bool IsCategoryEnabled(NotificationCategory category) const;
    void SetCategoryEnabled(NotificationCategory category, bool enabled);

    // Callbacks
    void RegisterNotificationCallback(NotificationCallback cb);
    void RegisterActionCallback(ActionCallback cb);
    void RegisterDismissCallback(DismissCallback cb);
    void RegisterErrorCallback(NotificationErrorCallback cb);
    void UnregisterCallbacks();

    // Statistics
    NotificationStatisticsSnapshot GetStatistics() const noexcept;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal
    void DispatchLoop();
    void QuietModeMonitorLoop();
    bool ShouldSuppress(const Notification& n) const;
    bool IsDuplicate(const Notification& n) const;
    bool CheckRateLimit();
    void DeliverNotification(Notification& n);
    void DeliverToast(const Notification& n);
    void DeliverBalloon(const Notification& n);
    void DeliverPopup(const Notification& n);
    void DeliverBanner(const Notification& n);
    void RecordToHistory(const Notification& n);
    void TrimHistory();
    void NotifyCallbackShown(const Notification& n);
    void NotifyError(const std::string& msg, int code);

    // Config
    NotificationConfiguration m_config;
    mutable std::shared_mutex m_configMutex;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    // Quiet mode
    std::atomic<QuietModeState> m_quietModeState{QuietModeState::Off};

    // Dispatch queue
    struct QueueEntry {
        Notification notification;
        TimePoint enqueuedAt;
    };
    std::deque<QueueEntry> m_queue;
    mutable std::shared_mutex m_queueMutex;
    std::condition_variable_any m_queueCv;

    // History
    std::deque<Notification> m_history;
    mutable std::shared_mutex m_historyMutex;

    // Deduplication (tag -> last-shown time)
    std::unordered_map<std::string, TimePoint> m_dedupMap;
    mutable std::mutex m_dedupMutex;

    // Rate limiting (sliding window of dispatch timestamps)
    std::deque<TimePoint> m_rateWindow;
    mutable std::mutex m_rateMutex;

    // Threads
    std::thread m_dispatchThread;
    std::thread m_quietModeThread;
    std::mutex m_dispatchStopMutex;
    std::condition_variable m_dispatchStopCv;

    // Callbacks
    NotificationCallback m_notifyCb;
    ActionCallback m_actionCb;
    DismissCallback m_dismissCb;
    NotificationErrorCallback m_errorCb;
    mutable std::mutex m_callbackMutex;

    // System tray
    NOTIFYICONDATAW m_trayIcon{};
    bool m_trayIconRegistered = false;
    HWND m_hiddenHwnd = nullptr;

    // Statistics
    NotificationStatistics m_stats;
};

// ============================================================================
// LIFECYCLE
// ============================================================================

bool NotificationManagerImpl::Initialize(const NotificationConfiguration& config) {
    ModuleStatus expected = ModuleStatus::Uninitialized;
    if (!m_status.compare_exchange_strong(expected, ModuleStatus::Initializing,
                                          std::memory_order_acq_rel)) {
        SS_LOG_WARN("NotifyMgr", "Already initialized (status={})",
                    static_cast<int>(expected));
        return false;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR("NotifyMgr", "Invalid configuration");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
    }

    m_stats.Reset();

    // Create hidden message-only window for Shell_NotifyIconW
    m_hiddenHwnd = CreateWindowExW(0, L"STATIC", L"ShadowStrikeNotifyHost",
                                    0, 0, 0, 0, 0,
                                    HWND_MESSAGE, nullptr, nullptr, nullptr);
    if (!m_hiddenHwnd) {
        SS_LOG_WARN("NotifyMgr", "Failed to create message window (err={}) — balloon tips may fail",
                    GetLastError());
    }

    m_running.store(true, std::memory_order_release);
    m_dispatchThread = std::thread([this] { DispatchLoop(); });
    m_quietModeThread = std::thread([this] { QuietModeMonitorLoop(); });

    m_initialized.store(true, std::memory_order_release);
    m_status.store(ModuleStatus::Running, std::memory_order_release);

    SS_LOG_INFO("NotifyMgr", "Initialized — rate_limit={}/min, dedup={}s, game_detect={}, meeting_detect={}",
                config.rateLimitPerMinute, config.dedupWindowSeconds,
                config.detectGameMode, config.detectMeetings);
    return true;
}

void NotificationManagerImpl::Shutdown() {
    if (!m_running.exchange(false, std::memory_order_acq_rel))
        return;

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    // Wake dispatch thread
    {
        std::unique_lock lock(m_queueMutex);
        m_queueCv.notify_all();
    }

    // Wake quiet mode monitor
    {
        std::unique_lock lock(m_dispatchStopMutex);
        m_dispatchStopCv.notify_all();
    }

    if (m_dispatchThread.joinable())
        m_dispatchThread.join();
    if (m_quietModeThread.joinable())
        m_quietModeThread.join();

    // Remove system tray icon
    if (m_trayIconRegistered) {
        Shell_NotifyIconW(NIM_DELETE, &m_trayIcon);
        m_trayIconRegistered = false;
    }

    if (m_hiddenHwnd) {
        DestroyWindow(m_hiddenHwnd);
        m_hiddenHwnd = nullptr;
    }

    // Drain queue
    {
        std::unique_lock lock(m_queueMutex);
        m_queue.clear();
    }

    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO("NotifyMgr", "Shutdown complete");
}

bool NotificationManagerImpl::UpdateConfiguration(const NotificationConfiguration& config) {
    if (!m_initialized.load(std::memory_order_acquire)) return false;
    if (!config.IsValid()) {
        SS_LOG_WARN("NotifyMgr", "Rejected invalid configuration update");
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
    }

    SS_LOG_INFO("NotifyMgr", "Configuration updated — rate_limit={}/min",
                config.rateLimitPerMinute);
    return true;
}

NotificationConfiguration NotificationManagerImpl::GetConfiguration() const {
    std::shared_lock lock(m_configMutex);
    return m_config;
}

// ============================================================================
// DISPATCH THREAD
// ============================================================================

void NotificationManagerImpl::DispatchLoop() {
    SS_LOG_DEBUG("NotifyMgr", "Dispatch thread started");

    while (m_running.load(std::memory_order_acquire)) {
        QueueEntry entry;
        {
            std::unique_lock lock(m_queueMutex);
            m_queueCv.wait(lock, [this] {
                return !m_queue.empty() || !m_running.load(std::memory_order_acquire);
            });

            if (!m_running.load(std::memory_order_acquire))
                break;

            if (m_queue.empty())
                continue;

            entry = std::move(m_queue.front());
            m_queue.pop_front();
        }

        // Check suppression
        if (ShouldSuppress(entry.notification)) {
            entry.notification.status = NotificationStatus::Suppressed;
            m_stats.totalSuppressed.fetch_add(1, std::memory_order_relaxed);
            RecordToHistory(entry.notification);
            continue;
        }

        // Check rate limit
        if (!CheckRateLimit()) {
            entry.notification.status = NotificationStatus::Suppressed;
            m_stats.rateLimitHits.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_DEBUG("NotifyMgr", "Rate limited notification id={}",
                         entry.notification.notificationId);
            RecordToHistory(entry.notification);
            continue;
        }

        // Check deduplication
        if (IsDuplicate(entry.notification)) {
            entry.notification.status = NotificationStatus::Suppressed;
            m_stats.totalSuppressed.fetch_add(1, std::memory_order_relaxed);
            RecordToHistory(entry.notification);
            continue;
        }

        DeliverNotification(entry.notification);
    }

    SS_LOG_DEBUG("NotifyMgr", "Dispatch thread stopped");
}

// ============================================================================
// QUIET MODE MONITOR THREAD
// ============================================================================

void NotificationManagerImpl::QuietModeMonitorLoop() {
    SS_LOG_DEBUG("NotifyMgr", "Quiet mode monitor started");

    while (m_running.load(std::memory_order_acquire)) {
        {
            std::unique_lock lock(m_dispatchStopMutex);
            m_dispatchStopCv.wait_for(lock, std::chrono::seconds(15), [this] {
                return !m_running.load(std::memory_order_acquire);
            });
        }
        if (!m_running.load(std::memory_order_acquire))
            break;

        // Check quiet hours schedule
        QuietHoursSchedule schedule;
        bool detectGame = false;
        bool detectMeeting = false;
        bool useFocusAssist = false;
        {
            std::shared_lock lock(m_configMutex);
            schedule = m_config.quietHours;
            detectGame = m_config.detectGameMode;
            detectMeeting = m_config.detectMeetings;
            useFocusAssist = m_config.useFocusAssist;
        }

        const auto currentManual = m_quietModeState.load(std::memory_order_acquire);
        if (currentManual == QuietModeState::Manual) {
            // Manual mode is sticky — don't override
            continue;
        }

        QuietModeState newState = QuietModeState::Off;

        if (schedule.enabled && schedule.IsActive()) {
            newState = QuietModeState::QuietHours;
        } else if (useFocusAssist) {
            int fa = GetFocusAssistStatus();
            if (fa == 1) newState = QuietModeState::PriorityOnly;
            else if (fa == 2) newState = QuietModeState::AlarmsOnly;
        }

        if (newState == QuietModeState::Off && detectGame && IsGameModeActive()) {
            newState = QuietModeState::Gaming;
        }

        if (newState == QuietModeState::Off && detectMeeting && IsInMeeting()) {
            newState = QuietModeState::Meeting;
        }

        const auto prev = m_quietModeState.exchange(newState, std::memory_order_acq_rel);
        if (prev != newState) {
            SS_LOG_INFO("NotifyMgr", "Quiet mode changed: {} -> {}",
                        std::string(GetQuietModeStateName(prev)),
                        std::string(GetQuietModeStateName(newState)));
        }
    }

    SS_LOG_DEBUG("NotifyMgr", "Quiet mode monitor stopped");
}

// ============================================================================
// SUPPRESSION / RATE LIMIT / DEDUP
// ============================================================================

bool NotificationManagerImpl::ShouldSuppress(const Notification& n) const {
    // Check global enable
    {
        std::shared_lock lock(m_configMutex);
        if (!m_config.enabled) return true;
        if (!m_config.preferences.enabled) return true;

        // Check minimum level
        if (static_cast<uint8_t>(n.level) < static_cast<uint8_t>(m_config.preferences.minimumLevel))
            return true;

        // Check category enable bitmask
        const uint32_t catBit = 1u << static_cast<uint8_t>(n.category);
        if (!(m_config.preferences.enabledCategories & catBit))
            return true;
    }

    // Check quiet mode
    if (!n.bypassQuietMode) {
        const auto qm = m_quietModeState.load(std::memory_order_acquire);
        switch (qm) {
            case QuietModeState::Off:
                break;
            case QuietModeState::PriorityOnly:
                if (n.level < NotificationLevel::Warning) {
                    m_stats.quietModeSuppressions.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
                break;
            case QuietModeState::AlarmsOnly:
                if (n.level < NotificationLevel::Critical) {
                    m_stats.quietModeSuppressions.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
                break;
            default:
                // QuietHours, Gaming, Meeting, Manual — suppress all but Critical
                if (n.level < NotificationLevel::Critical) {
                    m_stats.quietModeSuppressions.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
                break;
        }
    }

    return false;
}

bool NotificationManagerImpl::IsDuplicate(const Notification& n) const {
    bool dedupEnabled = false;
    uint32_t dedupWindow = 0;
    {
        std::shared_lock lock(m_configMutex);
        dedupEnabled = m_config.enableDeduplication;
        dedupWindow = m_config.dedupWindowSeconds;
    }

    if (!dedupEnabled || n.tag.empty()) return false;

    std::lock_guard lock(m_dedupMutex);

    // Periodic cleanup — remove expired entries to prevent unbounded growth
    const auto now = Clock::now();
    for (auto it = m_dedupMap.begin(); it != m_dedupMap.end(); ) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second).count();
        if (elapsed >= static_cast<int64_t>(dedupWindow)) {
            it = m_dedupMap.erase(it);
        } else {
            ++it;
        }
    }

    auto found = m_dedupMap.find(n.tag);
    if (found == m_dedupMap.end()) return false;

    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - found->second).count();
    return elapsed < static_cast<int64_t>(dedupWindow);
}

bool NotificationManagerImpl::CheckRateLimit() {
    size_t limit = 0;
    {
        std::shared_lock lock(m_configMutex);
        limit = m_config.rateLimitPerMinute;
    }

    if (limit == 0) return true;

    std::lock_guard lock(m_rateMutex);
    const auto now = Clock::now();
    const auto windowStart = now - std::chrono::minutes(1);

    // Trim old entries
    while (!m_rateWindow.empty() && m_rateWindow.front() < windowStart) {
        m_rateWindow.pop_front();
    }

    if (m_rateWindow.size() >= limit) return false;

    m_rateWindow.push_back(now);
    return true;
}

// ============================================================================
// DELIVERY
// ============================================================================

void NotificationManagerImpl::DeliverNotification(Notification& n) {
    try {
        n.shownTime = std::chrono::system_clock::now();

        switch (n.type) {
            case NotificationType::Toast:
                DeliverToast(n);
                break;
            case NotificationType::Balloon:
                DeliverBalloon(n);
                break;
            case NotificationType::Popup:
                DeliverPopup(n);
                break;
            case NotificationType::Banner:
                DeliverBanner(n);
                break;
            case NotificationType::Silent:
                n.status = NotificationStatus::Shown;
                break;
            default:
                SS_LOG_WARN("NotifyMgr", "Unknown notification type {} for id={}",
                            static_cast<int>(n.type), n.notificationId);
                n.status = NotificationStatus::Failed;
                m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
                RecordToHistory(n);
                return;
        }

        if (n.status == NotificationStatus::Shown) {
            m_stats.totalShown.fetch_add(1, std::memory_order_relaxed);

            const auto levelIdx = static_cast<size_t>(n.level);
            if (levelIdx < m_stats.byLevel.size())
                m_stats.byLevel[levelIdx].fetch_add(1, std::memory_order_relaxed);

            const auto catIdx = static_cast<size_t>(n.category);
            if (catIdx < m_stats.byCategory.size())
                m_stats.byCategory[catIdx].fetch_add(1, std::memory_order_relaxed);

            // Update dedup map
            if (!n.tag.empty()) {
                std::lock_guard lock(m_dedupMutex);
                m_dedupMap[n.tag] = Clock::now();
            }

            NotifyCallbackShown(n);
        }

        RecordToHistory(n);

    } catch (const std::exception& ex) {
        SS_LOG_ERROR("NotifyMgr", "Exception delivering notification id={}: {}",
                     n.notificationId, ex.what());
        n.status = NotificationStatus::Failed;
        m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
        RecordToHistory(n);
        NotifyError("Delivery failed: " + std::string(ex.what()), -1);
    }
}

// ============================================================================
// TOAST DELIVERY (Win32 Shell_NotifyIconW + balloon fallback)
// ============================================================================

void NotificationManagerImpl::DeliverToast(const Notification& n) {
    // Windows Toast via Shell_NotifyIconW balloon (COM-free approach)
    // Full WinRT toast would require COM activation, AppUserModelID registration,
    // and IToastNotification — wired when the UI shell is integrated.
    // For now, use reliable balloon tip which works from services and non-interactive sessions.
    DeliverBalloon(n);
}

void NotificationManagerImpl::DeliverBalloon(const Notification& n) {
    if (!m_trayIconRegistered) {
        // Register tray icon on first use
        ZeroMemory(&m_trayIcon, sizeof(m_trayIcon));
        m_trayIcon.cbSize = sizeof(NOTIFYICONDATAW);
        m_trayIcon.hWnd = m_hiddenHwnd;
        m_trayIcon.uID = 1;
        m_trayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
        m_trayIcon.uCallbackMessage = WM_APP + 100;

        // Use application icon
        m_trayIcon.hIcon = LoadIconW(nullptr, IDI_SHIELD);
        StringCchCopyW(m_trayIcon.szTip, ARRAYSIZE(m_trayIcon.szTip),
                       L"ShadowStrike EDR");

        m_trayIcon.uVersion = NOTIFYICON_VERSION_4;

        if (Shell_NotifyIconW(NIM_ADD, &m_trayIcon)) {
            Shell_NotifyIconW(NIM_SETVERSION, &m_trayIcon);
            m_trayIconRegistered = true;
        } else {
            SS_LOG_WARN("NotifyMgr", "Failed to register system tray icon (err={})",
                        GetLastError());
        }
    }

    NOTIFYICONDATAW balloon{};
    balloon.cbSize = sizeof(NOTIFYICONDATAW);
    balloon.hWnd = m_hiddenHwnd;
    balloon.uID = 1;
    balloon.uFlags = NIF_INFO;

    // Title (max 63 chars)
    StringCchCopyW(balloon.szInfoTitle, ARRAYSIZE(balloon.szInfoTitle),
                   n.title.empty() ? L"ShadowStrike" : n.title.c_str());

    // Message (max 255 chars)
    StringCchCopyW(balloon.szInfo, ARRAYSIZE(balloon.szInfo),
                   n.message.c_str());

    // Icon type based on level
    switch (n.level) {
        case NotificationLevel::Info:
        case NotificationLevel::Success:
            balloon.dwInfoFlags = NIIF_INFO;
            break;
        case NotificationLevel::Warning:
            balloon.dwInfoFlags = NIIF_WARNING;
            break;
        case NotificationLevel::Error:
        case NotificationLevel::Critical:
            balloon.dwInfoFlags = NIIF_ERROR;
            break;
    }

    if (n.timeoutMs > 0) {
        balloon.uTimeout = n.timeoutMs;
    }

    bool enableSounds = true;
    {
        std::shared_lock lock(m_configMutex);
        enableSounds = m_config.preferences.enableSounds;
    }
    if (!enableSounds) {
        balloon.dwInfoFlags |= NIIF_NOSOUND;
    }

    if (Shell_NotifyIconW(NIM_MODIFY, &balloon)) {
        const_cast<Notification&>(n).status = NotificationStatus::Shown;
    } else {
        SS_LOG_WARN("NotifyMgr", "Balloon notification failed (err={})", GetLastError());
        const_cast<Notification&>(n).status = NotificationStatus::Failed;
        m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
    }
}

void NotificationManagerImpl::DeliverPopup(const Notification& n) {
    // MessageBoxW-based popup (blocking on dispatch thread — acceptable for
    // EDR popups since queue continues after the user responds)
    UINT type = MB_OK | MB_TOPMOST | MB_SETFOREGROUND;
    switch (n.level) {
        case NotificationLevel::Info:
        case NotificationLevel::Success:
            type |= MB_ICONINFORMATION;
            break;
        case NotificationLevel::Warning:
            type |= MB_ICONWARNING;
            break;
        case NotificationLevel::Error:
        case NotificationLevel::Critical:
            type |= MB_ICONERROR;
            break;
    }

    // Build message with buttons info
    std::wstring body = n.message;
    if (!n.buttons.empty()) {
        body += L"\n\n";
        for (const auto& btn : n.buttons) {
            body += L"[" + btn.text + L"] ";
        }
    }

    const int result = MessageBoxW(nullptr, body.c_str(),
                                    n.title.empty() ? L"ShadowStrike EDR" : n.title.c_str(),
                                    type);

    const_cast<Notification&>(n).status = (result != 0)
        ? NotificationStatus::Shown
        : NotificationStatus::Failed;

    if (result == 0) {
        m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
    }
}

void NotificationManagerImpl::DeliverBanner(const Notification& n) {
    // Banner = toast semantics with auto-dismiss
    DeliverBalloon(n);
}

// ============================================================================
// HISTORY
// ============================================================================

void NotificationManagerImpl::RecordToHistory(const Notification& n) {
    std::unique_lock lock(m_historyMutex);
    m_history.push_back(n);
    TrimHistory();
}

void NotificationManagerImpl::TrimHistory() {
    // Caller must hold m_historyMutex
    while (m_history.size() > NotificationConstants::MAX_HISTORY_SIZE) {
        m_history.pop_front();
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void NotificationManagerImpl::NotifyCallbackShown(const Notification& n) {
    NotificationCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_notifyCb;
    }
    if (cb) {
        try { cb(n); }
        catch (const std::exception& ex) {
            SS_LOG_ERROR("NotifyMgr", "Notification callback threw: {}", ex.what());
        }
    }
}

void NotificationManagerImpl::NotifyError(const std::string& msg, int code) {
    NotificationErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCb;
    }
    if (cb) {
        try { cb(msg, code); }
        catch (...) {}
    }
}

// ============================================================================
// PUBLIC OPERATIONS (forwarded from PIMPL)
// ============================================================================

void NotificationManagerImpl::ShowSimple(const std::wstring& title,
                                          const std::wstring& message,
                                          NotificationLevel level) {
    Notification n;
    n.notificationId = GenerateNotificationId();
    n.title = title;
    n.message = message;
    n.level = level;
    n.type = NotificationType::Toast;
    n.category = NotificationCategory::General;
    n.createdTime = std::chrono::system_clock::now();

    {
        std::unique_lock lock(m_queueMutex);
        if (m_queue.size() >= NotificationConstants::MAX_QUEUE_SIZE) {
            SS_LOG_WARN("NotifyMgr", "Queue full ({}) — dropping notification id={}",
                        m_queue.size(), n.notificationId);
            m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        m_queue.push_back(QueueEntry{std::move(n), Clock::now()});
        m_queueCv.notify_one();
    }
}

std::string NotificationManagerImpl::ShowFull(const Notification& notification) {
    Notification n = notification;
    if (n.notificationId.empty())
        n.notificationId = GenerateNotificationId();
    if (n.createdTime == SystemTimePoint{})
        n.createdTime = std::chrono::system_clock::now();

    const std::string id = n.notificationId;

    {
        std::unique_lock lock(m_queueMutex);
        if (m_queue.size() >= NotificationConstants::MAX_QUEUE_SIZE) {
            SS_LOG_WARN("NotifyMgr", "Queue full — dropping notification id={}", id);
            m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
            return {};
        }
        m_queue.push_back(QueueEntry{std::move(n), Clock::now()});
        m_queueCv.notify_one();
    }

    return id;
}

void NotificationManagerImpl::ShowThreatAlertSimple(const std::wstring& threatName,
                                                     const std::wstring& filePath) {
    Notification n;
    n.notificationId = GenerateNotificationId();
    n.level = NotificationLevel::Critical;
    n.type = NotificationType::Toast;
    n.category = NotificationCategory::ThreatDetection;
    n.bypassQuietMode = true;
    n.title = L"\u26A0\uFE0F Threat Detected — " + threatName;
    n.message = L"Malicious file blocked:\n" + filePath;
    n.tag = "threat:" + ToNarrow(threatName);
    n.createdTime = std::chrono::system_clock::now();

    {
        std::unique_lock lock(m_queueMutex);
        if (m_queue.size() >= NotificationConstants::MAX_QUEUE_SIZE) {
            m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        // Threat alerts go to front of queue
        m_queue.push_front(QueueEntry{std::move(n), Clock::now()});
        m_queueCv.notify_one();
    }
}

std::string NotificationManagerImpl::ShowThreatAlertFull(const ThreatNotification& threat) {
    Notification n;
    n.notificationId = GenerateNotificationId();
    n.level = NotificationLevel::Critical;
    n.type = NotificationType::Toast;
    n.category = NotificationCategory::ThreatDetection;
    n.bypassQuietMode = true;
    n.createdTime = std::chrono::system_clock::now();

    n.title = L"\u26A0\uFE0F Threat Detected — " + threat.threatName;

    std::wstring body;
    body += L"File: " + threat.filePath + L"\n";
    body += L"Type: " + threat.threatType + L"\n";
    body += L"Severity: " + threat.severity + L"\n";
    body += L"Action: " + threat.actionTaken;
    n.message = body;

    n.tag = "threat:" + ToNarrow(threat.threatName);

    if (threat.showDetailsButton) {
        NotificationButton btn;
        btn.buttonId = "details";
        btn.text = L"View Details";
        btn.style = ButtonStyle::Primary;
        btn.action = "open_threat_details";
        n.buttons.push_back(std::move(btn));
    }

    if (threat.showRestoreButton) {
        NotificationButton btn;
        btn.buttonId = "restore";
        btn.text = L"Restore File";
        btn.style = ButtonStyle::Danger;
        btn.action = "restore_quarantined";
        n.buttons.push_back(std::move(btn));
    }

    const std::string id = n.notificationId;

    {
        std::unique_lock lock(m_queueMutex);
        if (m_queue.size() >= NotificationConstants::MAX_QUEUE_SIZE) {
            m_stats.totalFailed.fetch_add(1, std::memory_order_relaxed);
            return {};
        }
        m_queue.push_front(QueueEntry{std::move(n), Clock::now()});
        m_queueCv.notify_one();
    }

    return id;
}

bool NotificationManagerImpl::Update(const Notification& notification) {
    if (notification.notificationId.empty()) return false;

    std::unique_lock lock(m_historyMutex);
    for (auto& h : m_history) {
        if (h.notificationId == notification.notificationId) {
            h.title = notification.title;
            h.message = notification.message;
            h.level = notification.level;
            h.buttons = notification.buttons;
            h.data = notification.data;
            return true;
        }
    }
    return false;
}

bool NotificationManagerImpl::Remove(const std::string& notificationId) {
    if (notificationId.empty()) return false;

    std::unique_lock lock(m_historyMutex);
    auto it = std::find_if(m_history.begin(), m_history.end(),
                           [&](const Notification& n) { return n.notificationId == notificationId; });
    if (it != m_history.end()) {
        m_history.erase(it);
        return true;
    }
    return false;
}

bool NotificationManagerImpl::RemoveByTag(const std::string& tag) {
    if (tag.empty()) return false;

    std::unique_lock lock(m_historyMutex);
    const auto before = m_history.size();
    m_history.erase(
        std::remove_if(m_history.begin(), m_history.end(),
                       [&](const Notification& n) { return n.tag == tag; }),
        m_history.end());
    return m_history.size() < before;
}

void NotificationManagerImpl::ClearAll() {
    {
        std::unique_lock lock(m_queueMutex);
        m_queue.clear();
    }
    {
        std::unique_lock lock(m_historyMutex);
        m_history.clear();
    }

    if (m_trayIconRegistered) {
        // Clear current balloon
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = m_hiddenHwnd;
        nid.uID = 1;
        nid.uFlags = NIF_INFO;
        nid.szInfo[0] = L'\0';
        nid.szInfoTitle[0] = L'\0';
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    SS_LOG_DEBUG("NotifyMgr", "All notifications cleared");
}

// ============================================================================
// QUIET MODE
// ============================================================================

void NotificationManagerImpl::EnableQuietMode(QuietModeState state) {
    m_quietModeState.store(state, std::memory_order_release);
    SS_LOG_INFO("NotifyMgr", "Quiet mode enabled: {}",
                std::string(GetQuietModeStateName(state)));
}

void NotificationManagerImpl::DisableQuietMode() {
    m_quietModeState.store(QuietModeState::Off, std::memory_order_release);
    SS_LOG_INFO("NotifyMgr", "Quiet mode disabled");
}

bool NotificationManagerImpl::IsQuietModeActive() const noexcept {
    return m_quietModeState.load(std::memory_order_acquire) != QuietModeState::Off;
}

QuietModeState NotificationManagerImpl::GetQuietModeState() const noexcept {
    return m_quietModeState.load(std::memory_order_acquire);
}

void NotificationManagerImpl::SetQuietHoursSchedule(const QuietHoursSchedule& schedule) {
    std::unique_lock lock(m_configMutex);
    m_config.quietHours = schedule;
}

// ============================================================================
// HISTORY QUERIES
// ============================================================================

std::optional<Notification> NotificationManagerImpl::GetNotification(const std::string& notificationId) {
    std::shared_lock lock(m_historyMutex);
    for (const auto& n : m_history) {
        if (n.notificationId == notificationId)
            return n;
    }
    return std::nullopt;
}

std::vector<Notification> NotificationManagerImpl::GetRecentNotifications(size_t limit) {
    if (limit == 0) limit = 50;
    if (limit > NotificationConstants::MAX_HISTORY_SIZE)
        limit = NotificationConstants::MAX_HISTORY_SIZE;

    std::shared_lock lock(m_historyMutex);
    std::vector<Notification> result;
    result.reserve(std::min(limit, m_history.size()));

    size_t start = (m_history.size() > limit) ? (m_history.size() - limit) : 0;
    for (size_t i = start; i < m_history.size(); ++i) {
        result.push_back(m_history[i]);
    }

    // Most recent first
    std::reverse(result.begin(), result.end());
    return result;
}

std::vector<Notification> NotificationManagerImpl::GetNotificationsByCategory(
    NotificationCategory category, size_t limit) {

    if (limit == 0) limit = 50;
    if (limit > NotificationConstants::MAX_HISTORY_SIZE)
        limit = NotificationConstants::MAX_HISTORY_SIZE;

    std::shared_lock lock(m_historyMutex);
    std::vector<Notification> result;
    result.reserve(std::min(limit, m_history.size()));

    for (auto it = m_history.rbegin(); it != m_history.rend() && result.size() < limit; ++it) {
        if (it->category == category)
            result.push_back(*it);
    }

    return result;
}

void NotificationManagerImpl::ClearHistory() {
    std::unique_lock lock(m_historyMutex);
    m_history.clear();
    SS_LOG_DEBUG("NotifyMgr", "History cleared");
}

// ============================================================================
// PREFERENCES
// ============================================================================

void NotificationManagerImpl::SetPreferences(const NotificationPreferences& prefs) {
    if (!prefs.IsValid()) {
        SS_LOG_WARN("NotifyMgr", "Rejected invalid preferences");
        return;
    }
    std::unique_lock lock(m_configMutex);
    m_config.preferences = prefs;
}

NotificationPreferences NotificationManagerImpl::GetPreferences() const {
    std::shared_lock lock(m_configMutex);
    return m_config.preferences;
}

bool NotificationManagerImpl::IsCategoryEnabled(NotificationCategory category) const {
    std::shared_lock lock(m_configMutex);
    const uint32_t catBit = 1u << static_cast<uint8_t>(category);
    return (m_config.preferences.enabledCategories & catBit) != 0;
}

void NotificationManagerImpl::SetCategoryEnabled(NotificationCategory category, bool enabled) {
    std::unique_lock lock(m_configMutex);
    const uint32_t catBit = 1u << static_cast<uint8_t>(category);
    if (enabled)
        m_config.preferences.enabledCategories |= catBit;
    else
        m_config.preferences.enabledCategories &= ~catBit;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void NotificationManagerImpl::RegisterNotificationCallback(NotificationCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_notifyCb = std::move(cb);
}

void NotificationManagerImpl::RegisterActionCallback(ActionCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_actionCb = std::move(cb);
}

void NotificationManagerImpl::RegisterDismissCallback(DismissCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_dismissCb = std::move(cb);
}

void NotificationManagerImpl::RegisterErrorCallback(NotificationErrorCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCb = std::move(cb);
}

void NotificationManagerImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_notifyCb = nullptr;
    m_actionCb = nullptr;
    m_dismissCb = nullptr;
    m_errorCb = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

NotificationStatisticsSnapshot NotificationManagerImpl::GetStatistics() const noexcept {
    return m_stats.TakeSnapshot();
}

void NotificationManagerImpl::ResetStatistics() {
    m_stats.Reset();
    SS_LOG_DEBUG("NotifyMgr", "Statistics reset");
}

bool NotificationManagerImpl::SelfTest() {
    SS_LOG_INFO("NotifyMgr", "Running self-test...");

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR("NotifyMgr", "Self-test failed: not initialized");
        return false;
    }

    // Verify dispatch thread is alive
    if (!m_dispatchThread.joinable()) {
        SS_LOG_ERROR("NotifyMgr", "Self-test failed: dispatch thread not running");
        return false;
    }

    // Verify quiet mode monitor is alive
    if (!m_quietModeThread.joinable()) {
        SS_LOG_ERROR("NotifyMgr", "Self-test failed: quiet mode monitor not running");
        return false;
    }

    // Verify queue is not stuck (no items older than 30 seconds)
    {
        std::shared_lock lock(m_queueMutex);
        if (!m_queue.empty()) {
            const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                Clock::now() - m_queue.front().enqueuedAt).count();
            if (age > 30) {
                SS_LOG_WARN("NotifyMgr", "Self-test warning: oldest queue item is {}s old", age);
            }
        }
    }

    SS_LOG_INFO("NotifyMgr", "Self-test passed");
    return true;
}

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> NotificationManager::s_instanceCreated{false};

NotificationManager::NotificationManager()
    : m_impl(std::make_unique<NotificationManagerImpl>()) {}

NotificationManager::~NotificationManager() = default;

NotificationManager& NotificationManager::Instance() noexcept {
    static NotificationManager instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool NotificationManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// FORWARDING — LIFECYCLE
// ============================================================================

bool NotificationManager::Initialize(const NotificationConfiguration& config) {
    return m_impl->Initialize(config);
}

void NotificationManager::Shutdown() {
    m_impl->Shutdown();
}

bool NotificationManager::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus NotificationManager::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool NotificationManager::UpdateConfiguration(const NotificationConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

NotificationConfiguration NotificationManager::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// FORWARDING — NOTIFICATION OPERATIONS
// ============================================================================

void NotificationManager::Show(const std::wstring& title, const std::wstring& message,
                                NotificationLevel level) {
    m_impl->ShowSimple(title, message, level);
}

std::string NotificationManager::Show(const Notification& notification) {
    return m_impl->ShowFull(notification);
}

void NotificationManager::ShowThreatAlert(const std::wstring& threatName,
                                           const std::wstring& filePath) {
    m_impl->ShowThreatAlertSimple(threatName, filePath);
}

std::string NotificationManager::ShowThreatAlert(const ThreatNotification& threat) {
    return m_impl->ShowThreatAlertFull(threat);
}

bool NotificationManager::Update(const Notification& notification) {
    return m_impl->Update(notification);
}

bool NotificationManager::Remove(const std::string& notificationId) {
    return m_impl->Remove(notificationId);
}

bool NotificationManager::RemoveByTag(const std::string& tag) {
    return m_impl->RemoveByTag(tag);
}

void NotificationManager::ClearAll() {
    m_impl->ClearAll();
}

// ============================================================================
// FORWARDING — QUIET MODE
// ============================================================================

void NotificationManager::EnableQuietMode(QuietModeState state) {
    m_impl->EnableQuietMode(state);
}

void NotificationManager::DisableQuietMode() {
    m_impl->DisableQuietMode();
}

bool NotificationManager::IsQuietModeActive() const noexcept {
    return m_impl->IsQuietModeActive();
}

QuietModeState NotificationManager::GetQuietModeState() const noexcept {
    return m_impl->GetQuietModeState();
}

void NotificationManager::SetQuietHoursSchedule(const QuietHoursSchedule& schedule) {
    m_impl->SetQuietHoursSchedule(schedule);
}

// ============================================================================
// FORWARDING — HISTORY
// ============================================================================

std::optional<Notification> NotificationManager::GetNotification(
    const std::string& notificationId) {
    return m_impl->GetNotification(notificationId);
}

std::vector<Notification> NotificationManager::GetRecentNotifications(size_t limit) {
    return m_impl->GetRecentNotifications(limit);
}

std::vector<Notification> NotificationManager::GetNotificationsByCategory(
    NotificationCategory category, size_t limit) {
    return m_impl->GetNotificationsByCategory(category, limit);
}

void NotificationManager::ClearHistory() {
    m_impl->ClearHistory();
}

// ============================================================================
// FORWARDING — PREFERENCES
// ============================================================================

void NotificationManager::SetPreferences(const NotificationPreferences& prefs) {
    m_impl->SetPreferences(prefs);
}

NotificationPreferences NotificationManager::GetPreferences() const {
    return m_impl->GetPreferences();
}

bool NotificationManager::IsCategoryEnabled(NotificationCategory category) const {
    return m_impl->IsCategoryEnabled(category);
}

void NotificationManager::SetCategoryEnabled(NotificationCategory category, bool enabled) {
    m_impl->SetCategoryEnabled(category, enabled);
}

// ============================================================================
// FORWARDING — CALLBACKS
// ============================================================================

void NotificationManager::RegisterNotificationCallback(NotificationCallback callback) {
    m_impl->RegisterNotificationCallback(std::move(callback));
}

void NotificationManager::RegisterActionCallback(ActionCallback callback) {
    m_impl->RegisterActionCallback(std::move(callback));
}

void NotificationManager::RegisterDismissCallback(DismissCallback callback) {
    m_impl->RegisterDismissCallback(std::move(callback));
}

void NotificationManager::RegisterErrorCallback(NotificationErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void NotificationManager::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

// ============================================================================
// FORWARDING — STATISTICS
// ============================================================================

NotificationStatisticsSnapshot NotificationManager::GetStatistics() const {
    return m_impl->GetStatistics();
}

void NotificationManager::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool NotificationManager::SelfTest() {
    return m_impl->SelfTest();
}

std::string NotificationManager::GetVersionString() noexcept {
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                  NotificationConstants::VERSION_MAJOR,
                  NotificationConstants::VERSION_MINOR,
                  NotificationConstants::VERSION_PATCH);
    return buf;
}

// ============================================================================
// STRUCT METHODS
// ============================================================================

std::string NotificationButton::ToJson() const {
    std::string j = "{";
    j += "\"buttonId\":\"" + JsonEscape(buttonId) + "\",";
    j += "\"text\":\"" + JsonEscape(ToNarrow(text)) + "\",";
    j += "\"style\":" + std::to_string(static_cast<int>(style)) + ",";
    j += "\"action\":\"" + JsonEscape(action) + "\",";
    j += "\"arguments\":\"" + JsonEscape(arguments) + "\",";
    j += "\"isDismiss\":" + std::string(isDismiss ? "true" : "false");
    j += "}";
    return j;
}

std::string Notification::ToJson() const {
    std::string j = "{";
    j += "\"notificationId\":\"" + JsonEscape(notificationId) + "\",";
    j += "\"level\":\"" + std::string(GetNotificationLevelName(level)) + "\",";
    j += "\"type\":\"" + std::string(GetNotificationTypeName(type)) + "\",";
    j += "\"category\":\"" + std::string(GetNotificationCategoryName(category)) + "\",";
    j += "\"title\":\"" + JsonEscape(ToNarrow(title)) + "\",";
    j += "\"message\":\"" + JsonEscape(ToNarrow(message)) + "\",";
    j += "\"status\":\"" + std::string(GetNotificationStatusName(status)) + "\",";
    j += "\"priority\":" + std::to_string(priority) + ",";
    j += "\"bypassQuietMode\":" + std::string(bypassQuietMode ? "true" : "false") + ",";
    j += "\"tag\":\"" + JsonEscape(tag) + "\",";
    j += "\"group\":\"" + JsonEscape(group) + "\",";
    j += "\"createdTime\":\"" + SystemTimeToIso8601(createdTime) + "\",";
    if (shownTime) {
        j += "\"shownTime\":\"" + SystemTimeToIso8601(*shownTime) + "\",";
    }
    j += "\"buttons\":[";
    for (size_t i = 0; i < buttons.size(); ++i) {
        if (i > 0) j += ",";
        j += buttons[i].ToJson();
    }
    j += "],";
    j += "\"data\":{";
    bool first = true;
    for (const auto& [k, v] : data) {
        if (!first) j += ",";
        j += "\"" + JsonEscape(k) + "\":\"" + JsonEscape(v) + "\"";
        first = false;
    }
    j += "}";
    j += "}";
    return j;
}

std::string ThreatNotification::ToJson() const {
    std::string j = "{";
    j += "\"threatName\":\"" + JsonEscape(ToNarrow(threatName)) + "\",";
    j += "\"filePath\":\"" + JsonEscape(ToNarrow(filePath)) + "\",";
    j += "\"threatType\":\"" + JsonEscape(ToNarrow(threatType)) + "\",";
    j += "\"severity\":\"" + JsonEscape(ToNarrow(severity)) + "\",";
    j += "\"actionTaken\":\"" + JsonEscape(ToNarrow(actionTaken)) + "\",";
    j += "\"showRestoreButton\":" + std::string(showRestoreButton ? "true" : "false") + ",";
    j += "\"showDetailsButton\":" + std::string(showDetailsButton ? "true" : "false");
    j += "}";
    return j;
}

bool NotificationPreferences::IsValid() const noexcept {
    return soundVolume >= 0 && soundVolume <= 100 &&
           maxConcurrent > 0 && maxConcurrent <= 20;
}

bool QuietHoursSchedule::IsActive() const {
    if (!enabled) return false;

    SYSTEMTIME st{};
    GetLocalTime(&st);

    // Check day-of-week bitmask (Sunday = 0 = bit 0)
    if (!(daysOfWeek & (1u << st.wDayOfWeek)))
        return false;

    const int nowMinutes = st.wHour * 60 + st.wMinute;
    const int startMinutes = startHour * 60 + startMinute;
    const int endMinutes = endHour * 60 + endMinute;

    if (startMinutes <= endMinutes) {
        return nowMinutes >= startMinutes && nowMinutes < endMinutes;
    } else {
        // Wraps midnight (e.g., 22:00 - 07:00)
        return nowMinutes >= startMinutes || nowMinutes < endMinutes;
    }
}

bool NotificationConfiguration::IsValid() const noexcept {
    if (rateLimitPerMinute == 0 || rateLimitPerMinute > 1000)
        return false;
    if (dedupWindowSeconds > 3600)
        return false;
    if (!preferences.IsValid())
        return false;
    // Validate quiet hours time ranges
    if (quietHours.enabled) {
        if (quietHours.startHour < 0 || quietHours.startHour > 23) return false;
        if (quietHours.endHour < 0 || quietHours.endHour > 23) return false;
        if (quietHours.startMinute < 0 || quietHours.startMinute > 59) return false;
        if (quietHours.endMinute < 0 || quietHours.endMinute > 59) return false;
    }
    if (!customSoundsFolder.empty()) {
        const std::wstring ws = customSoundsFolder.wstring();
        if (ws.find(L"..") != std::wstring::npos) return false;
    }
    return true;
}

// ============================================================================
// STATISTICS
// ============================================================================

void NotificationStatistics::Reset() noexcept {
    totalShown.store(0, std::memory_order_relaxed);
    totalClicked.store(0, std::memory_order_relaxed);
    totalDismissed.store(0, std::memory_order_relaxed);
    totalExpired.store(0, std::memory_order_relaxed);
    totalSuppressed.store(0, std::memory_order_relaxed);
    totalFailed.store(0, std::memory_order_relaxed);
    totalButtonClicks.store(0, std::memory_order_relaxed);
    rateLimitHits.store(0, std::memory_order_relaxed);
    quietModeSuppressions.store(0, std::memory_order_relaxed);
    for (auto& a : byLevel) a.store(0, std::memory_order_relaxed);
    for (auto& a : byCategory) a.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

NotificationStatisticsSnapshot NotificationStatistics::TakeSnapshot() const noexcept {
    NotificationStatisticsSnapshot snap;
    snap.totalShown = totalShown.load(std::memory_order_relaxed);
    snap.totalClicked = totalClicked.load(std::memory_order_relaxed);
    snap.totalDismissed = totalDismissed.load(std::memory_order_relaxed);
    snap.totalExpired = totalExpired.load(std::memory_order_relaxed);
    snap.totalSuppressed = totalSuppressed.load(std::memory_order_relaxed);
    snap.totalFailed = totalFailed.load(std::memory_order_relaxed);
    snap.totalButtonClicks = totalButtonClicks.load(std::memory_order_relaxed);
    snap.rateLimitHits = rateLimitHits.load(std::memory_order_relaxed);
    snap.quietModeSuppressions = quietModeSuppressions.load(std::memory_order_relaxed);
    for (size_t i = 0; i < byLevel.size(); ++i)
        snap.byLevel[i] = byLevel[i].load(std::memory_order_relaxed);
    for (size_t i = 0; i < byCategory.size(); ++i)
        snap.byCategory[i] = byCategory[i].load(std::memory_order_relaxed);
    snap.uptimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    return snap;
}

std::string NotificationStatisticsSnapshot::ToJson() const {
    std::string j = "{";
    j += "\"totalShown\":" + std::to_string(totalShown) + ",";
    j += "\"totalClicked\":" + std::to_string(totalClicked) + ",";
    j += "\"totalDismissed\":" + std::to_string(totalDismissed) + ",";
    j += "\"totalExpired\":" + std::to_string(totalExpired) + ",";
    j += "\"totalSuppressed\":" + std::to_string(totalSuppressed) + ",";
    j += "\"totalFailed\":" + std::to_string(totalFailed) + ",";
    j += "\"totalButtonClicks\":" + std::to_string(totalButtonClicks) + ",";
    j += "\"rateLimitHits\":" + std::to_string(rateLimitHits) + ",";
    j += "\"quietModeSuppressions\":" + std::to_string(quietModeSuppressions) + ",";
    j += "\"uptimeSeconds\":" + std::to_string(uptimeSeconds) + ",";
    j += "\"byLevel\":[";
    for (size_t i = 0; i < byLevel.size(); ++i) {
        if (i > 0) j += ",";
        j += std::to_string(byLevel[i]);
    }
    j += "],\"byCategory\":[";
    for (size_t i = 0; i < byCategory.size(); ++i) {
        if (i > 0) j += ",";
        j += std::to_string(byCategory[i]);
    }
    j += "]}";
    return j;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetNotificationLevelName(NotificationLevel level) noexcept {
    switch (level) {
        case NotificationLevel::Info:     return "Info";
        case NotificationLevel::Success:  return "Success";
        case NotificationLevel::Warning:  return "Warning";
        case NotificationLevel::Error:    return "Error";
        case NotificationLevel::Critical: return "Critical";
        default:                          return "Unknown";
    }
}

std::string_view GetNotificationTypeName(NotificationType type) noexcept {
    switch (type) {
        case NotificationType::Toast:   return "Toast";
        case NotificationType::Balloon: return "Balloon";
        case NotificationType::Popup:   return "Popup";
        case NotificationType::Banner:  return "Banner";
        case NotificationType::Silent:  return "Silent";
        default:                        return "Unknown";
    }
}

std::string_view GetNotificationCategoryName(NotificationCategory category) noexcept {
    switch (category) {
        case NotificationCategory::General:          return "General";
        case NotificationCategory::ThreatDetection:  return "ThreatDetection";
        case NotificationCategory::ScanComplete:     return "ScanComplete";
        case NotificationCategory::UpdateAvailable:  return "UpdateAvailable";
        case NotificationCategory::SystemHealth:     return "SystemHealth";
        case NotificationCategory::PolicyAlert:      return "PolicyAlert";
        case NotificationCategory::QuarantineAction: return "QuarantineAction";
        case NotificationCategory::BackupComplete:   return "BackupComplete";
        case NotificationCategory::LicenseExpiry:    return "LicenseExpiry";
        case NotificationCategory::Custom:           return "Custom";
        default:                                     return "Unknown";
    }
}

std::string_view GetNotificationStatusName(NotificationStatus status) noexcept {
    switch (status) {
        case NotificationStatus::Pending:    return "Pending";
        case NotificationStatus::Shown:      return "Shown";
        case NotificationStatus::Clicked:    return "Clicked";
        case NotificationStatus::Dismissed:  return "Dismissed";
        case NotificationStatus::Expired:    return "Expired";
        case NotificationStatus::Suppressed: return "Suppressed";
        case NotificationStatus::Failed:     return "Failed";
        default:                             return "Unknown";
    }
}

std::string_view GetQuietModeStateName(QuietModeState state) noexcept {
    switch (state) {
        case QuietModeState::Off:          return "Off";
        case QuietModeState::QuietHours:   return "QuietHours";
        case QuietModeState::Gaming:       return "Gaming";
        case QuietModeState::Meeting:      return "Meeting";
        case QuietModeState::PriorityOnly: return "PriorityOnly";
        case QuietModeState::AlarmsOnly:   return "AlarmsOnly";
        case QuietModeState::Manual:       return "Manual";
        default:                           return "Unknown";
    }
}

std::wstring GetLevelIcon(NotificationLevel level) {
    switch (level) {
        case NotificationLevel::Info:     return L"\u2139\uFE0F";   // ℹ️
        case NotificationLevel::Success:  return L"\u2705";          // ✅
        case NotificationLevel::Warning:  return L"\u26A0\uFE0F";   // ⚠️
        case NotificationLevel::Error:    return L"\u274C";          // ❌
        case NotificationLevel::Critical: return L"\U0001F6A8";      // 🚨
        default:                          return L"\u2753";          // ❓
    }
}

}  // namespace Communication
}  // namespace ShadowStrike

