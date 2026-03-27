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
#include "SettingsManager.hpp"
#include "../Utils/JSONUtils.hpp"

#include <thread>
#include <unordered_map>
#include <algorithm>
#include <ctime>
#include <cstdio>
#include <shlobj.h>

using Json = ShadowStrike::Utils::JSON::Json;

namespace ShadowStrike {
namespace Config {

// ============================================================================
// ANONYMOUS NAMESPACE — HELPERS
// ============================================================================

namespace {

constexpr const wchar_t* LOG_CAT = L"Settings";

// ── Wide ↔ UTF-8 ──────────────────────────────────────────────────────────

std::string WideToUtf8(std::wstring_view wide) noexcept {
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

std::wstring Utf8ToWide(std::string_view utf8) noexcept {
    if (utf8.empty()) return {};
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
        nullptr, 0);
    if (needed <= 0) return {};
    std::wstring result(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()),
        result.data(), needed);
    return result;
}

// ── RAII registry key guard ────────────────────────────────────────────────

struct RegKeyGuard {
    HKEY key = nullptr;
    ~RegKeyGuard() { if (key) ::RegCloseKey(key); }
    RegKeyGuard() = default;
    RegKeyGuard(const RegKeyGuard&) = delete;
    RegKeyGuard& operator=(const RegKeyGuard&) = delete;
};

// ── Timestamp helpers ──────────────────────────────────────────────────────

int64_t SystemTimePointToMs(const SystemTimePoint& tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()).count();
}

SystemTimePoint MsToSystemTimePoint(int64_t ms) noexcept {
    return SystemTimePoint(std::chrono::milliseconds(ms));
}

// ── Default keyboard shortcuts ─────────────────────────────────────────────

std::map<std::string, std::string> GetDefaultShortcuts() {
    return {
        {"scan",       "Ctrl+S"},
        {"quickScan",  "Ctrl+Shift+S"},
        {"fullScan",   "Ctrl+Shift+F"},
        {"settings",   "Ctrl+,"},
        {"help",       "F1"},
        {"quit",       "Alt+F4"},
        {"toggleTheme","Ctrl+T"},
        {"refresh",    "F5"}
    };
}

// ── JSON ↔ struct helpers ──────────────────────────────────────────────────

Json ThemeSettingsToObj(const ThemeSettings& ts) {
    return Json{
        {"theme",              static_cast<uint8_t>(ts.theme)},
        {"accent",             static_cast<uint8_t>(ts.accent)},
        {"customAccentRgb",    ts.customAccentRgb},
        {"customThemePath",    ts.customThemePath},
        {"enableAnimations",   ts.enableAnimations},
        {"enableTransparency", ts.enableTransparency},
        {"fontScale",          ts.fontScale}
    };
}

ThemeSettings ThemeSettingsFromObj(const Json& j) {
    ThemeSettings ts;
    if (j.is_object()) {
        ts.theme              = static_cast<Theme>(j.value("theme", static_cast<uint8_t>(Theme::System)));
        ts.accent             = static_cast<AccentColor>(j.value("accent", static_cast<uint8_t>(AccentColor::Blue)));
        ts.customAccentRgb    = j.value("customAccentRgb", 0x0078D4u);
        ts.customThemePath    = j.value("customThemePath", std::string{});
        ts.enableAnimations   = j.value("enableAnimations", true);
        ts.enableTransparency = j.value("enableTransparency", true);
        ts.fontScale          = j.value("fontScale", 1.0f);
        if (ts.fontScale < 0.5f) ts.fontScale = 0.5f;
        if (ts.fontScale > 3.0f) ts.fontScale = 3.0f;
    }
    return ts;
}

Json LocalizationSettingsToObj(const LocalizationSettings& ls) {
    return Json{
        {"languageCode",       ls.languageCode},
        {"dateFormat",         static_cast<uint8_t>(ls.dateFormat)},
        {"timeFormat",         static_cast<uint8_t>(ls.timeFormat)},
        {"decimalSeparator",   std::string(1, ls.decimalSeparator)},
        {"thousandsSeparator",  std::string(1, ls.thousandsSeparator)},
        {"use24HourFormat",    ls.use24HourFormat},
        {"firstDayOfWeek",     ls.firstDayOfWeek}
    };
}

LocalizationSettings LocalizationSettingsFromObj(const Json& j) {
    LocalizationSettings ls;
    if (j.is_object()) {
        ls.languageCode      = j.value("languageCode", std::string{"en-US"});
        ls.dateFormat        = static_cast<DateFormat>(j.value("dateFormat", static_cast<uint8_t>(DateFormat::System)));
        ls.timeFormat        = static_cast<TimeFormat>(j.value("timeFormat", static_cast<uint8_t>(TimeFormat::System)));
        auto decSep          = j.value("decimalSeparator", std::string{"."});
        ls.decimalSeparator  = decSep.empty() ? '.' : decSep[0];
        auto thousSep        = j.value("thousandsSeparator", std::string{","});
        ls.thousandsSeparator = thousSep.empty() ? ',' : thousSep[0];
        ls.use24HourFormat   = j.value("use24HourFormat", false);
        ls.firstDayOfWeek    = j.value("firstDayOfWeek", static_cast<uint8_t>(0));
    }
    return ls;
}

Json NotificationSettingsToObj(const NotificationSettings& ns) {
    return Json{
        {"enabled",                 ns.enabled},
        {"level",                   static_cast<uint8_t>(ns.level)},
        {"sound",                   static_cast<uint8_t>(ns.sound)},
        {"customSoundPath",         ns.customSoundPath},
        {"showToast",               ns.showToast},
        {"toastDurationSeconds",    ns.toastDurationSeconds},
        {"doNotDisturbEnabled",     ns.doNotDisturbEnabled},
        {"dndStartHour",            ns.dndStartHour},
        {"dndEndHour",              ns.dndEndHour},
        {"scheduledQuietHours",     ns.scheduledQuietHours},
        {"showScanProgress",        ns.showScanProgress},
        {"showUpdateNotifications", ns.showUpdateNotifications}
    };
}

NotificationSettings NotificationSettingsFromObj(const Json& j) {
    NotificationSettings ns;
    if (j.is_object()) {
        ns.enabled                = j.value("enabled", true);
        ns.level                  = static_cast<NotificationLevel>(j.value("level", static_cast<uint8_t>(NotificationLevel::All)));
        ns.sound                  = static_cast<SoundSetting>(j.value("sound", static_cast<uint8_t>(SoundSetting::Important)));
        ns.customSoundPath        = j.value("customSoundPath", std::string{});
        ns.showToast              = j.value("showToast", true);
        ns.toastDurationSeconds   = j.value("toastDurationSeconds", 5u);
        ns.doNotDisturbEnabled    = j.value("doNotDisturbEnabled", false);
        ns.dndStartHour           = j.value("dndStartHour", 22u);
        ns.dndEndHour             = j.value("dndEndHour", 7u);
        ns.scheduledQuietHours    = j.value("scheduledQuietHours", false);
        ns.showScanProgress       = j.value("showScanProgress", true);
        ns.showUpdateNotifications= j.value("showUpdateNotifications", true);
    }
    return ns;
}

Json StartupSettingsToObj(const StartupSettings& ss) {
    return Json{
        {"startWithWindows",      ss.startWithWindows},
        {"startMinimized",        ss.startMinimized},
        {"minimizeToTray",        ss.minimizeToTray},
        {"closeToTray",           ss.closeToTray},
        {"trayBehavior",          static_cast<uint8_t>(ss.trayBehavior)},
        {"showSplashScreen",      ss.showSplashScreen},
        {"checkUpdatesOnStartup", ss.checkUpdatesOnStartup},
        {"quickScanOnStartup",    ss.quickScanOnStartup}
    };
}

StartupSettings StartupSettingsFromObj(const Json& j) {
    StartupSettings ss;
    if (j.is_object()) {
        ss.startWithWindows      = j.value("startWithWindows", true);
        ss.startMinimized        = j.value("startMinimized", false);
        ss.minimizeToTray        = j.value("minimizeToTray", true);
        ss.closeToTray           = j.value("closeToTray", true);
        ss.trayBehavior          = static_cast<TrayIconBehavior>(j.value("trayBehavior", static_cast<uint8_t>(TrayIconBehavior::AlwaysShow)));
        ss.showSplashScreen      = j.value("showSplashScreen", true);
        ss.checkUpdatesOnStartup = j.value("checkUpdatesOnStartup", true);
        ss.quickScanOnStartup    = j.value("quickScanOnStartup", false);
    }
    return ss;
}

Json AccessibilitySettingsToObj(const AccessibilitySettings& as) {
    return Json{
        {"screenReaderSupport", as.screenReaderSupport},
        {"highContrastMode",    as.highContrastMode},
        {"reduceMotion",        as.reduceMotion},
        {"largeText",           as.largeText},
        {"keyboardShortcuts",   as.keyboardShortcuts},
        {"focusIndicators",     as.focusIndicators},
        {"tooltipDelayMs",      as.tooltipDelayMs},
        {"cursorBlinkRate",     as.cursorBlinkRate}
    };
}

AccessibilitySettings AccessibilitySettingsFromObj(const Json& j) {
    AccessibilitySettings as;
    if (j.is_object()) {
        as.screenReaderSupport = j.value("screenReaderSupport", true);
        as.highContrastMode    = j.value("highContrastMode", false);
        as.reduceMotion        = j.value("reduceMotion", false);
        as.largeText           = j.value("largeText", false);
        as.keyboardShortcuts   = j.value("keyboardShortcuts", true);
        as.focusIndicators     = j.value("focusIndicators", true);
        as.tooltipDelayMs      = j.value("tooltipDelayMs", 500u);
        as.cursorBlinkRate     = j.value("cursorBlinkRate", 530u);
    }
    return as;
}

Json WindowSettingsToObj(const WindowSettings& ws) {
    return Json{
        {"rememberPosition",  ws.rememberPosition},
        {"x",                 ws.windowX},
        {"y",                 ws.windowY},
        {"width",             ws.windowWidth},
        {"height",            ws.windowHeight},
        {"isMaximized",       ws.isMaximized},
        {"sidebarWidth",      ws.sidebarWidth},
        {"detailsPaneVisible",ws.detailsPaneVisible}
    };
}

WindowSettings WindowSettingsFromObj(const Json& j) {
    WindowSettings ws;
    if (j.is_object()) {
        ws.rememberPosition  = j.value("rememberPosition", true);
        ws.windowX           = j.value("x", 100);
        ws.windowY           = j.value("y", 100);
        ws.windowWidth       = j.value("width", 1024u);
        ws.windowHeight      = j.value("height", 768u);
        ws.isMaximized       = j.value("isMaximized", false);
        ws.sidebarWidth      = j.value("sidebarWidth", 200u);
        ws.detailsPaneVisible= j.value("detailsPaneVisible", true);
    }
    return ws;
}

Json ScanUISettingsToObj(const ScanUISettings& su) {
    return Json{
        {"showCurrentFile",       su.showCurrentFile},
        {"showStatistics",        su.showStatistics},
        {"showTimeRemaining",     su.showTimeRemaining},
        {"autoCloseOnClean",      su.autoCloseOnClean},
        {"autoCloseDelaySeconds", su.autoCloseDelaySeconds},
        {"defaultViewMode",       su.defaultViewMode}
    };
}

ScanUISettings ScanUISettingsFromObj(const Json& j) {
    ScanUISettings su;
    if (j.is_object()) {
        su.showCurrentFile       = j.value("showCurrentFile", true);
        su.showStatistics        = j.value("showStatistics", true);
        su.showTimeRemaining     = j.value("showTimeRemaining", true);
        su.autoCloseOnClean      = j.value("autoCloseOnClean", false);
        su.autoCloseDelaySeconds = j.value("autoCloseDelaySeconds", 5u);
        su.defaultViewMode       = j.value("defaultViewMode", std::string{"list"});
    }
    return su;
}

// ── Full UserSettings ↔ JSON ───────────────────────────────────────────────

Json UserSettingsToObj(const UserSettings& s) {
    Json jShortcuts = Json::object();
    for (const auto& [action, shortcut] : s.keyboardShortcuts) {
        jShortcuts[action] = shortcut;
    }

    Json jRecent = Json::array();
    for (const auto& item : s.recentItems) {
        jRecent.push_back(WideToUtf8(item));
    }

    Json jFavorites = Json::array();
    for (const auto& loc : s.favoriteLocations) {
        jFavorites.push_back(WideToUtf8(loc));
    }

    return Json{
        {"version",           s.settingsVersion},
        {"theme",             ThemeSettingsToObj(s.theme)},
        {"localization",      LocalizationSettingsToObj(s.localization)},
        {"notifications",     NotificationSettingsToObj(s.notifications)},
        {"startup",           StartupSettingsToObj(s.startup)},
        {"accessibility",     AccessibilitySettingsToObj(s.accessibility)},
        {"window",            WindowSettingsToObj(s.window)},
        {"scanUI",            ScanUISettingsToObj(s.scanUI)},
        {"keyboardShortcuts", jShortcuts},
        {"recentItems",       jRecent},
        {"favoriteLocations", jFavorites},
        {"lastModified",      SystemTimePointToMs(s.lastModified)}
    };
}

UserSettings UserSettingsFromObj(const Json& j) {
    UserSettings s;
    if (!j.is_object()) return s;

    s.settingsVersion = j.value("version", 1u);
    if (j.contains("theme"))          s.theme          = ThemeSettingsFromObj(j["theme"]);
    if (j.contains("localization"))   s.localization   = LocalizationSettingsFromObj(j["localization"]);
    if (j.contains("notifications"))  s.notifications  = NotificationSettingsFromObj(j["notifications"]);
    if (j.contains("startup"))        s.startup        = StartupSettingsFromObj(j["startup"]);
    if (j.contains("accessibility"))  s.accessibility  = AccessibilitySettingsFromObj(j["accessibility"]);
    if (j.contains("window"))         s.window         = WindowSettingsFromObj(j["window"]);
    if (j.contains("scanUI"))         s.scanUI         = ScanUISettingsFromObj(j["scanUI"]);

    if (j.contains("keyboardShortcuts") && j["keyboardShortcuts"].is_object()) {
        for (auto& [k, v] : j["keyboardShortcuts"].items()) {
            if (v.is_string()) {
                s.keyboardShortcuts[k] = v.get<std::string>();
            }
        }
    }

    if (j.contains("recentItems") && j["recentItems"].is_array()) {
        for (const auto& item : j["recentItems"]) {
            if (item.is_string()) {
                s.recentItems.push_back(Utf8ToWide(item.get<std::string>()));
            }
        }
        if (s.recentItems.size() > SettingsConstants::MAX_RECENT_FILES) {
            s.recentItems.resize(SettingsConstants::MAX_RECENT_FILES);
        }
    }

    if (j.contains("favoriteLocations") && j["favoriteLocations"].is_array()) {
        for (const auto& loc : j["favoriteLocations"]) {
            if (loc.is_string()) {
                s.favoriteLocations.push_back(Utf8ToWide(loc.get<std::string>()));
            }
        }
    }

    if (j.contains("lastModified") && j["lastModified"].is_number_integer()) {
        s.lastModified = MsToSystemTimePoint(j["lastModified"].get<int64_t>());
    }

    return s;
}

} // anonymous namespace

// ============================================================================
// STRUCT ToJson() / IsValid() / Reset() IMPLEMENTATIONS
// ============================================================================

std::string ThemeSettings::ToJson() const {
    try { return ThemeSettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

std::string LocalizationSettings::ToJson() const {
    try { return LocalizationSettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

std::string NotificationSettings::ToJson() const {
    try { return NotificationSettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

std::string StartupSettings::ToJson() const {
    try { return StartupSettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

std::string AccessibilitySettings::ToJson() const {
    try { return AccessibilitySettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

std::string WindowSettings::ToJson() const {
    try { return WindowSettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

std::string ScanUISettings::ToJson() const {
    try { return ScanUISettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

std::string UserSettings::ToJson() const {
    try { return UserSettingsToObj(*this).dump(2); }
    catch (...) { return "{}"; }
}

bool UserSettings::IsValid() const noexcept {
    if (theme.fontScale < 0.5f || theme.fontScale > 3.0f) return false;
    if (localization.languageCode.empty()) return false;
    if (recentItems.size() > SettingsConstants::MAX_RECENT_FILES) return false;
    if (keyboardShortcuts.size() > SettingsConstants::MAX_CUSTOM_SHORTCUTS) return false;
    if (notifications.dndStartHour > 23 || notifications.dndEndHour > 23) return false;
    return true;
}

std::string SettingsChangeEvent::ToJson() const {
    try {
        Json j{
            {"category",  category},
            {"key",       key},
            {"timestamp", SystemTimePointToMs(timestamp)}
        };
        return j.dump(2);
    }
    catch (...) { return "{}"; }
}

void SettingsStatistics::Reset() noexcept {
    totalLoads.store(0, std::memory_order_relaxed);
    totalSaves.store(0, std::memory_order_relaxed);
    settingChanges.store(0, std::memory_order_relaxed);
    resets.store(0, std::memory_order_relaxed);
    imports.store(0, std::memory_order_relaxed);
    exports.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string SettingsStatistics::ToJson() const {
    try {
        const auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - startTime).count();
        Json j{
            {"totalLoads",     totalLoads.load(std::memory_order_relaxed)},
            {"totalSaves",     totalSaves.load(std::memory_order_relaxed)},
            {"settingChanges", settingChanges.load(std::memory_order_relaxed)},
            {"resets",         resets.load(std::memory_order_relaxed)},
            {"imports",        imports.load(std::memory_order_relaxed)},
            {"exports",        exports.load(std::memory_order_relaxed)},
            {"uptimeSeconds",  uptimeMs / 1000}
        };
        return j.dump(2);
    }
    catch (...) { return "{}"; }
}

bool SettingsManagerConfiguration::IsValid() const noexcept {
    if (enableAutoSave && autoSaveIntervalSeconds < 5) return false;
    if (maxBackups > 100) return false;
    return true;
}

// ============================================================================
// SETTINGS MANAGER IMPL
// ============================================================================

class SettingsManagerImpl {
public:
    SettingsManagerConfiguration m_config;
    SettingsStatus               m_status{SettingsStatus::Uninitialized};
    UserSettings                 m_currentSettings;
    mutable std::shared_mutex    m_mutex;

    std::unordered_map<uint64_t, SettingsChangeCallback>  m_changeCallbacks;
    std::vector<ThemeChangeCallback>                      m_themeCallbacks;
    std::vector<LanguageChangeCallback>                   m_languageCallbacks;
    ErrorCallback                                         m_errorCallback;
    uint64_t                                              m_nextCallbackId{1};

    // ID tracking for theme/language callbacks (ID → index in vector)
    std::unordered_map<uint64_t, size_t> m_themeCallbackIds;
    std::unordered_map<uint64_t, size_t> m_languageCallbackIds;

    SettingsStatistics      m_stats;
    std::atomic<bool>       m_dirty{false};
    std::atomic<bool>       m_shutdownRequested{false};
    std::jthread            m_autoSaveThread;
    bool                    m_initialized{false};

    // ── Internal methods ───────────────────────────────────────────────────

    void NotifySettingsChanged(const std::string& category, const std::string& key) {
        SettingsChangeEvent event;
        event.category  = category;
        event.key       = key;
        event.timestamp = std::chrono::system_clock::now();

        std::vector<SettingsChangeCallback> cbs;
        {
            std::shared_lock lock(m_mutex);
            cbs.reserve(m_changeCallbacks.size());
            for (const auto& [id, cb] : m_changeCallbacks) {
                if (cb) cbs.push_back(cb);
            }
        }
        for (const auto& cb : cbs) {
            try { cb(event); } catch (...) {
                SS_LOG_WARN(LOG_CAT, L"Settings change callback threw an exception");
            }
        }
        m_stats.settingChanges.fetch_add(1, std::memory_order_relaxed);
    }

    void NotifyThemeChanged(Theme newTheme) {
        std::vector<ThemeChangeCallback> cbs;
        {
            std::shared_lock lock(m_mutex);
            cbs = m_themeCallbacks;
        }
        for (const auto& cb : cbs) {
            if (!cb) continue;
            try { cb(newTheme); } catch (...) {
                SS_LOG_WARN(LOG_CAT, L"Theme change callback threw an exception");
            }
        }
    }

    void NotifyLanguageChanged(const std::string& lang) {
        std::vector<LanguageChangeCallback> cbs;
        {
            std::shared_lock lock(m_mutex);
            cbs = m_languageCallbacks;
        }
        for (const auto& cb : cbs) {
            if (!cb) continue;
            try { cb(lang); } catch (...) {
                SS_LOG_WARN(LOG_CAT, L"Language change callback threw an exception");
            }
        }
    }

    void NotifyError(const std::string& msg, int code) {
        ErrorCallback cb;
        {
            std::shared_lock lock(m_mutex);
            cb = m_errorCallback;
        }
        if (cb) {
            try { cb(msg, code); } catch (...) {}
        }
    }

    void CreateBackup() {
        if (!m_config.createBackupOnSave) return;

        const auto srcPath = m_config.settingsFilePath.wstring();
        if (!Utils::FileUtils::Exists(srcPath)) return;

        const auto bakPath = srcPath + L".bak";
        if (!::CopyFileW(srcPath.c_str(), bakPath.c_str(), FALSE)) {
            SS_LOG_WARN(LOG_CAT, L"Failed to create settings backup file");
        }
    }

    bool SaveToFile(const UserSettings& settings) {
        try {
            CreateBackup();

            const Json j = UserSettingsToObj(settings);
            const std::string content = j.dump(2);

            const auto filePath = m_config.settingsFilePath.wstring();

            // Ensure parent directory exists
            const auto parentDir = m_config.settingsFilePath.parent_path();
            if (!parentDir.empty()) {
                Utils::FileUtils::CreateDirectories(parentDir.wstring());
            }

            Utils::FileUtils::Error err{};
            if (!Utils::FileUtils::WriteAllTextUtf8Atomic(filePath, content, &err)) {
                SS_LOG_ERROR(LOG_CAT, L"Failed to save settings file: win32=%lu", err.win32);
                NotifyError("Failed to save settings: " + err.message, static_cast<int>(err.win32));
                return false;
            }

            m_stats.totalSaves.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(LOG_CAT, L"Settings saved successfully");
            return true;
        }
        catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CAT, L"Exception saving settings: %hs", ex.what());
            NotifyError(std::string("Exception saving settings: ") + ex.what(), -1);
            return false;
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CAT, L"Unknown exception saving settings");
            return false;
        }
    }

    UserSettings LoadFromFile() {
        const auto filePath = m_config.settingsFilePath.wstring();

        if (!Utils::FileUtils::Exists(filePath)) {
            SS_LOG_INFO(LOG_CAT, L"Settings file not found, using defaults");
            UserSettings defaults;
            defaults.keyboardShortcuts = GetDefaultShortcuts();
            defaults.lastModified = std::chrono::system_clock::now();
            return defaults;
        }

        std::string content;
        Utils::FileUtils::Error fileErr{};
        if (!Utils::FileUtils::ReadAllTextUtf8(filePath, content, &fileErr)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to read settings file: win32=%lu", fileErr.win32);
            NotifyError("Failed to read settings: " + fileErr.message, static_cast<int>(fileErr.win32));
            UserSettings defaults;
            defaults.keyboardShortcuts = GetDefaultShortcuts();
            return defaults;
        }

        Json j;
        Utils::JSON::Error jsonErr{};
        if (!Utils::JSON::Parse(content, j, &jsonErr)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to parse settings JSON (line %zu, col %zu)",
                         jsonErr.line, jsonErr.column);
            NotifyError("Failed to parse settings: " + jsonErr.message, -2);
            UserSettings defaults;
            defaults.keyboardShortcuts = GetDefaultShortcuts();
            return defaults;
        }

        m_stats.totalLoads.fetch_add(1, std::memory_order_relaxed);
        UserSettings loaded = UserSettingsFromObj(j);

        // Ensure keyboard shortcuts have defaults for any missing entries
        auto defaults = GetDefaultShortcuts();
        for (const auto& [action, shortcut] : defaults) {
            if (loaded.keyboardShortcuts.find(action) == loaded.keyboardShortcuts.end()) {
                loaded.keyboardShortcuts[action] = shortcut;
            }
        }

        SS_LOG_INFO(LOG_CAT, L"Settings loaded successfully (version %u)", loaded.settingsVersion);
        return loaded;
    }

    void AutoSaveLoop(std::stop_token stopToken) {
        SS_LOG_DEBUG(LOG_CAT, L"Auto-save thread started (interval=%u s)",
                     m_config.autoSaveIntervalSeconds);
        while (!stopToken.stop_requested() && !m_shutdownRequested.load(std::memory_order_acquire)) {
            // Sleep in 100 ms increments so we can respond to stop requests promptly
            const uint32_t ticks = m_config.autoSaveIntervalSeconds * 10u;
            for (uint32_t i = 0; i < ticks; ++i) {
                if (stopToken.stop_requested() || m_shutdownRequested.load(std::memory_order_acquire)) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (m_dirty.exchange(false, std::memory_order_acq_rel)) {
                UserSettings snapshot;
                {
                    std::shared_lock lock(m_mutex);
                    snapshot = m_currentSettings;
                }
                {
                    std::unique_lock lock(m_mutex);
                    m_status = SettingsStatus::Saving;
                }
                const bool ok = SaveToFile(snapshot);
                {
                    std::unique_lock lock(m_mutex);
                    m_status = SettingsStatus::Running;
                }
                if (!ok) {
                    SS_LOG_WARN(LOG_CAT, L"Auto-save failed, will retry next interval");
                    m_dirty.store(true, std::memory_order_release);
                }
            }
        }
        SS_LOG_DEBUG(LOG_CAT, L"Auto-save thread stopped");
    }

    void MarkDirty() noexcept {
        m_dirty.store(true, std::memory_order_release);
    }
};

// ============================================================================
// STATIC MEMBER DEFINITION
// ============================================================================

std::atomic<bool> SettingsManager::s_instanceCreated{false};

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

SettingsManager::SettingsManager()
    : m_impl(std::make_unique<SettingsManagerImpl>()) {}

SettingsManager::~SettingsManager() {
    if (m_impl && m_impl->m_initialized) {
        Shutdown();
    }
}

// ============================================================================
// SINGLETON
// ============================================================================

SettingsManager& SettingsManager::Instance() noexcept {
    static SettingsManager instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool SettingsManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool SettingsManager::Initialize(const SettingsManagerConfiguration& config) {
    auto& impl = *m_impl;
    std::unique_lock lock(impl.m_mutex);

    if (impl.m_initialized) {
        SS_LOG_WARN(LOG_CAT, L"SettingsManager already initialized");
        return true;
    }

    impl.m_status = SettingsStatus::Initializing;
    impl.m_config = config;

    // Default settings file path: next to executable
    if (impl.m_config.settingsFilePath.empty()) {
        wchar_t exePath[MAX_PATH]{};
        ::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        impl.m_config.settingsFilePath =
            fs::path(exePath).parent_path() / SettingsConstants::SETTINGS_FILE_NAME;
    }

    if (!impl.m_config.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"Invalid SettingsManager configuration");
        impl.m_status = SettingsStatus::Error;
        return false;
    }

    SS_LOG_INFO(LOG_CAT, L"Initializing SettingsManager v%hs", GetVersionString().c_str());

    // Load settings from file (or create defaults)
    lock.unlock();
    auto loaded = impl.LoadFromFile();
    lock.lock();

    impl.m_currentSettings = std::move(loaded);
    impl.m_stats.Reset();
    impl.m_shutdownRequested.store(false, std::memory_order_release);
    impl.m_dirty.store(false, std::memory_order_release);

    // Start auto-save thread
    if (impl.m_config.enableAutoSave) {
        impl.m_autoSaveThread = std::jthread(
            [&impl](std::stop_token st) { impl.AutoSaveLoop(st); });
    }

    impl.m_initialized = true;
    impl.m_status = SettingsStatus::Running;
    SS_LOG_INFO(LOG_CAT, L"SettingsManager initialized successfully");
    return true;
}

void SettingsManager::Shutdown() {
    auto& impl = *m_impl;

    {
        std::unique_lock lock(impl.m_mutex);
        if (!impl.m_initialized) return;
        impl.m_status = SettingsStatus::Stopping;
    }

    SS_LOG_INFO(LOG_CAT, L"SettingsManager shutting down");

    impl.m_shutdownRequested.store(true, std::memory_order_release);

    // Stop auto-save thread
    if (impl.m_autoSaveThread.joinable()) {
        impl.m_autoSaveThread.request_stop();
        impl.m_autoSaveThread.join();
    }

    // Final save if dirty
    if (impl.m_dirty.load(std::memory_order_acquire)) {
        UserSettings snapshot;
        {
            std::shared_lock lock(impl.m_mutex);
            snapshot = impl.m_currentSettings;
        }
        impl.SaveToFile(snapshot);
        impl.m_dirty.store(false, std::memory_order_release);
    }

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_changeCallbacks.clear();
        impl.m_themeCallbacks.clear();
        impl.m_languageCallbacks.clear();
        impl.m_themeCallbackIds.clear();
        impl.m_languageCallbackIds.clear();
        impl.m_errorCallback = nullptr;
        impl.m_initialized = false;
        impl.m_status = SettingsStatus::Stopped;
    }

    SS_LOG_INFO(LOG_CAT, L"SettingsManager stopped");
}

bool SettingsManager::IsInitialized() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_initialized;
}

SettingsStatus SettingsManager::GetStatus() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// LOAD / SAVE
// ============================================================================

UserSettings SettingsManager::Load() {
    auto& impl = *m_impl;
    auto loaded = impl.LoadFromFile();

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings = loaded;
        impl.m_dirty.store(false, std::memory_order_release);
    }

    return loaded;
}

bool SettingsManager::Save(const UserSettings& settings) {
    auto& impl = *m_impl;

    if (!settings.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"Refusing to save invalid settings");
        impl.NotifyError("Invalid settings rejected", -3);
        return false;
    }

    UserSettings toSave = settings;
    toSave.lastModified = std::chrono::system_clock::now();

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings = toSave;
        impl.m_status = SettingsStatus::Saving;
    }

    const bool ok = impl.SaveToFile(toSave);

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_status = SettingsStatus::Running;
    }

    if (ok) {
        impl.m_dirty.store(false, std::memory_order_release);
        impl.NotifySettingsChanged("all", "save");
    }

    return ok;
}

bool SettingsManager::SaveCurrent() {
    auto& impl = *m_impl;

    UserSettings snapshot;
    {
        std::shared_lock lock(impl.m_mutex);
        snapshot = impl.m_currentSettings;
    }
    snapshot.lastModified = std::chrono::system_clock::now();

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.lastModified = snapshot.lastModified;
        impl.m_status = SettingsStatus::Saving;
    }

    const bool ok = impl.SaveToFile(snapshot);

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_status = SettingsStatus::Running;
    }

    if (ok) {
        impl.m_dirty.store(false, std::memory_order_release);
    }

    return ok;
}

UserSettings SettingsManager::GetCurrentSettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings;
}

void SettingsManager::SetCurrentSettings(const UserSettings& settings) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings = settings;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("all", "setCurrentSettings");
}

// ============================================================================
// THEME
// ============================================================================

ThemeSettings SettingsManager::GetThemeSettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.theme;
}

void SettingsManager::SetTheme(Theme theme) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.theme.theme = theme;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("theme", "theme");
    impl.NotifyThemeChanged(theme);
}

void SettingsManager::SetAccentColor(AccentColor accent) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.theme.accent = accent;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("theme", "accent");
}

void SettingsManager::SetCustomAccentColor(uint32_t rgb) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.theme.accent = AccentColor::Custom;
        impl.m_currentSettings.theme.customAccentRgb = rgb;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("theme", "customAccentRgb");
}

Theme SettingsManager::GetEffectiveTheme() const {
    Theme current;
    {
        std::shared_lock lock(m_impl->m_mutex);
        current = m_impl->m_currentSettings.theme.theme;
    }
    if (current == Theme::System) {
        return GetSystemTheme();
    }
    return current;
}

// ============================================================================
// LOCALIZATION
// ============================================================================

LocalizationSettings SettingsManager::GetLocalizationSettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.localization;
}

void SettingsManager::SetLanguage(const std::string& languageCode) {
    auto& impl = *m_impl;
    if (languageCode.empty()) {
        SS_LOG_WARN(LOG_CAT, L"Rejected empty language code");
        return;
    }
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.localization.languageCode = languageCode;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("localization", "languageCode");
    impl.NotifyLanguageChanged(languageCode);
}

std::vector<std::pair<std::string, std::string>> SettingsManager::GetAvailableLanguages() const {
    return {
        {"en-US", "English (United States)"},
        {"en-GB", "English (United Kingdom)"},
        {"de-DE", "Deutsch (Deutschland)"},
        {"fr-FR", "Français (France)"},
        {"es-ES", "Español (España)"},
        {"it-IT", "Italiano (Italia)"},
        {"pt-BR", "Português (Brasil)"},
        {"ja-JP", "日本語 (日本)"},
        {"ko-KR", "한국어 (대한민국)"},
        {"zh-CN", "中文 (简体)"},
        {"zh-TW", "中文 (繁體)"},
        {"ru-RU", "Русский (Россия)"},
        {"ar-SA", "العربية (السعودية)"},
        {"he-IL", "עברית (ישראל)"},
        {"pl-PL", "Polski (Polska)"},
        {"nl-NL", "Nederlands (Nederland)"},
        {"sv-SE", "Svenska (Sverige)"},
        {"da-DK", "Dansk (Danmark)"},
        {"fi-FI", "Suomi (Suomi)"},
        {"nb-NO", "Norsk bokmål (Norge)"},
        {"tr-TR", "Türkçe (Türkiye)"},
        {"cs-CZ", "Čeština (Česko)"},
        {"hu-HU", "Magyar (Magyarország)"},
        {"uk-UA", "Українська (Україна)"}
    };
}

void SettingsManager::SetDateFormat(DateFormat format) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.localization.dateFormat = format;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("localization", "dateFormat");
}

void SettingsManager::SetTimeFormat(TimeFormat format) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.localization.timeFormat = format;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("localization", "timeFormat");
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================

NotificationSettings SettingsManager::GetNotificationSettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.notifications;
}

void SettingsManager::SetNotificationSettings(const NotificationSettings& settings) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.notifications = settings;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("notifications", "all");
}

void SettingsManager::SetNotificationsEnabled(bool enabled) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.notifications.enabled = enabled;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("notifications", "enabled");
}

void SettingsManager::SetNotificationLevel(NotificationLevel level) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.notifications.level = level;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("notifications", "level");
}

void SettingsManager::SetDoNotDisturb(bool enabled) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.notifications.doNotDisturbEnabled = enabled;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("notifications", "doNotDisturbEnabled");
}

// ============================================================================
// STARTUP
// ============================================================================

StartupSettings SettingsManager::GetStartupSettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.startup;
}

void SettingsManager::SetStartupSettings(const StartupSettings& settings) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.startup = settings;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("startup", "all");
}

bool SettingsManager::SetStartWithWindows(bool enabled) {
    auto& impl = *m_impl;

    RegKeyGuard guard;
    LONG result = ::RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE | KEY_QUERY_VALUE, &guard.key);
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(LOG_CAT, L"Failed to open Run registry key: %ld", result);
        return false;
    }

    if (enabled) {
        wchar_t exePath[MAX_PATH]{};
        const DWORD len = ::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            SS_LOG_ERROR(LOG_CAT, L"GetModuleFileNameW failed for SetStartWithWindows");
            return false;
        }
        // Wrap in quotes for paths with spaces
        std::wstring quotedPath = L"\"" + std::wstring(exePath) + L"\"";
        result = ::RegSetValueExW(
            guard.key, L"ShadowStrike", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(quotedPath.c_str()),
            static_cast<DWORD>((quotedPath.size() + 1) * sizeof(wchar_t)));
    } else {
        result = ::RegDeleteValueW(guard.key, L"ShadowStrike");
        if (result == ERROR_FILE_NOT_FOUND) {
            result = ERROR_SUCCESS; // Value doesn't exist, that's fine
        }
    }

    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(LOG_CAT, L"Failed to %ls Run registry value: %ld",
                     enabled ? L"set" : L"delete", result);
        return false;
    }

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.startup.startWithWindows = enabled;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("startup", "startWithWindows");

    SS_LOG_INFO(LOG_CAT, L"Start with Windows %ls", enabled ? L"enabled" : L"disabled");
    return true;
}

bool SettingsManager::GetStartWithWindows() const {
    RegKeyGuard guard;
    if (::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_READ, &guard.key) != ERROR_SUCCESS) {
        return false;
    }
    DWORD type = 0;
    DWORD size = 0;
    return ::RegQueryValueExW(guard.key, L"ShadowStrike", nullptr, &type, nullptr, &size)
           == ERROR_SUCCESS;
}

// ============================================================================
// ACCESSIBILITY
// ============================================================================

AccessibilitySettings SettingsManager::GetAccessibilitySettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.accessibility;
}

void SettingsManager::SetAccessibilitySettings(const AccessibilitySettings& settings) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.accessibility = settings;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("accessibility", "all");
}

void SettingsManager::SetHighContrastMode(bool enabled) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.accessibility.highContrastMode = enabled;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("accessibility", "highContrastMode");
    if (enabled) {
        impl.NotifyThemeChanged(Theme::HighContrast);
    }
}

void SettingsManager::SetLargeText(bool enabled) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.accessibility.largeText = enabled;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("accessibility", "largeText");
}

// ============================================================================
// WINDOW
// ============================================================================

WindowSettings SettingsManager::GetWindowSettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.window;
}

void SettingsManager::SetWindowSettings(const WindowSettings& settings) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.window = settings;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("window", "all");
}

void SettingsManager::SaveWindowPosition(int32_t x, int32_t y, uint32_t width, uint32_t height, bool maximized) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        auto& w = impl.m_currentSettings.window;
        if (!w.rememberPosition) return;
        w.windowX     = x;
        w.windowY     = y;
        w.windowWidth  = width;
        w.windowHeight = height;
        w.isMaximized  = maximized;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
}

// ============================================================================
// RECENT ITEMS & FAVORITES
// ============================================================================

void SettingsManager::AddRecentItem(const std::wstring& path) {
    auto& impl = *m_impl;
    if (path.empty()) return;

    {
        std::unique_lock lock(impl.m_mutex);
        auto& items = impl.m_currentSettings.recentItems;

        // Remove existing duplicates
        items.erase(
            std::remove(items.begin(), items.end(), path),
            items.end());

        // Insert at front
        items.insert(items.begin(), path);

        // Trim to max
        if (items.size() > SettingsConstants::MAX_RECENT_FILES) {
            items.resize(SettingsConstants::MAX_RECENT_FILES);
        }

        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
}

std::vector<std::wstring> SettingsManager::GetRecentItems() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.recentItems;
}

void SettingsManager::ClearRecentItems() {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.recentItems.clear();
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("recentItems", "clear");
}

void SettingsManager::AddFavoriteLocation(const std::wstring& path) {
    auto& impl = *m_impl;
    if (path.empty()) return;

    {
        std::unique_lock lock(impl.m_mutex);
        auto& favs = impl.m_currentSettings.favoriteLocations;
        // Avoid duplicates
        if (std::find(favs.begin(), favs.end(), path) == favs.end()) {
            favs.push_back(path);
        }
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("favoriteLocations", "add");
}

void SettingsManager::RemoveFavoriteLocation(const std::wstring& path) {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        auto& favs = impl.m_currentSettings.favoriteLocations;
        favs.erase(std::remove(favs.begin(), favs.end(), path), favs.end());
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("favoriteLocations", "remove");
}

std::vector<std::wstring> SettingsManager::GetFavoriteLocations() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.favoriteLocations;
}

// ============================================================================
// KEYBOARD SHORTCUTS
// ============================================================================

void SettingsManager::SetKeyboardShortcut(const std::string& action, const std::string& shortcut) {
    auto& impl = *m_impl;
    if (action.empty()) return;

    {
        std::unique_lock lock(impl.m_mutex);
        if (impl.m_currentSettings.keyboardShortcuts.size() >= SettingsConstants::MAX_CUSTOM_SHORTCUTS
            && impl.m_currentSettings.keyboardShortcuts.find(action) == impl.m_currentSettings.keyboardShortcuts.end()) {
            SS_LOG_WARN(LOG_CAT, L"Maximum keyboard shortcuts reached (%zu)",
                        SettingsConstants::MAX_CUSTOM_SHORTCUTS);
            return;
        }
        impl.m_currentSettings.keyboardShortcuts[action] = shortcut;
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("keyboardShortcuts", action);
}

std::optional<std::string> SettingsManager::GetKeyboardShortcut(const std::string& action) const {
    std::shared_lock lock(m_impl->m_mutex);
    const auto& shortcuts = m_impl->m_currentSettings.keyboardShortcuts;
    auto it = shortcuts.find(action);
    if (it != shortcuts.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::map<std::string, std::string> SettingsManager::GetAllKeyboardShortcuts() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSettings.keyboardShortcuts;
}

void SettingsManager::ResetKeyboardShortcuts() {
    auto& impl = *m_impl;
    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings.keyboardShortcuts = GetDefaultShortcuts();
        impl.m_currentSettings.lastModified = std::chrono::system_clock::now();
    }
    impl.MarkDirty();
    impl.NotifySettingsChanged("keyboardShortcuts", "reset");
}

// ============================================================================
// IMPORT / EXPORT
// ============================================================================

bool SettingsManager::ExportSettings(const fs::path& filePath) const {
    auto& impl = *m_impl;

    if (filePath.empty()) {
        SS_LOG_ERROR(LOG_CAT, L"ExportSettings called with empty path");
        return false;
    }

    UserSettings snapshot;
    {
        std::shared_lock lock(impl.m_mutex);
        snapshot = impl.m_currentSettings;
    }

    try {
        const Json j = UserSettingsToObj(snapshot);
        const std::string content = j.dump(2);

        Utils::FileUtils::Error err{};
        if (!Utils::FileUtils::WriteAllTextUtf8Atomic(filePath.wstring(), content, &err)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to export settings: win32=%lu", err.win32);
            return false;
        }

        impl.m_stats.exports.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(LOG_CAT, L"Settings exported successfully");
        return true;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"Exception exporting settings: %hs", ex.what());
        return false;
    }
}

bool SettingsManager::ImportSettings(const fs::path& filePath) {
    auto& impl = *m_impl;

    if (filePath.empty()) {
        SS_LOG_ERROR(LOG_CAT, L"ImportSettings called with empty path");
        return false;
    }

    const auto wpath = filePath.wstring();
    if (!Utils::FileUtils::Exists(wpath)) {
        SS_LOG_ERROR(LOG_CAT, L"Import file does not exist");
        return false;
    }

    std::string content;
    Utils::FileUtils::Error fileErr{};
    if (!Utils::FileUtils::ReadAllTextUtf8(wpath, content, &fileErr)) {
        SS_LOG_ERROR(LOG_CAT, L"Failed to read import file: win32=%lu", fileErr.win32);
        return false;
    }

    Json j;
    Utils::JSON::Error jsonErr{};
    if (!Utils::JSON::Parse(content, j, &jsonErr)) {
        SS_LOG_ERROR(LOG_CAT, L"Failed to parse imported settings JSON");
        return false;
    }

    UserSettings imported = UserSettingsFromObj(j);
    if (!imported.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"Imported settings failed validation");
        return false;
    }

    imported.lastModified = std::chrono::system_clock::now();

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings = std::move(imported);
    }

    impl.MarkDirty();
    impl.m_stats.imports.fetch_add(1, std::memory_order_relaxed);
    impl.NotifySettingsChanged("all", "import");
    SS_LOG_INFO(LOG_CAT, L"Settings imported successfully");
    return true;
}

void SettingsManager::ResetToDefaults() {
    auto& impl = *m_impl;
    UserSettings defaults;
    defaults.keyboardShortcuts = GetDefaultShortcuts();
    defaults.lastModified = std::chrono::system_clock::now();

    {
        std::unique_lock lock(impl.m_mutex);
        impl.m_currentSettings = defaults;
    }

    impl.MarkDirty();
    impl.m_stats.resets.fetch_add(1, std::memory_order_relaxed);
    impl.NotifySettingsChanged("all", "reset");
    SS_LOG_INFO(LOG_CAT, L"Settings reset to factory defaults");
}

UserSettings SettingsManager::GetFactoryDefaults() const {
    UserSettings defaults;
    defaults.keyboardShortcuts = GetDefaultShortcuts();
    return defaults;
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t SettingsManager::RegisterChangeCallback(SettingsChangeCallback callback) {
    auto& impl = *m_impl;
    if (!callback) return 0;
    std::unique_lock lock(impl.m_mutex);
    const uint64_t id = impl.m_nextCallbackId++;
    impl.m_changeCallbacks[id] = std::move(callback);
    return id;
}

uint64_t SettingsManager::RegisterThemeChangeCallback(ThemeChangeCallback callback) {
    auto& impl = *m_impl;
    if (!callback) return 0;
    std::unique_lock lock(impl.m_mutex);
    const uint64_t id = impl.m_nextCallbackId++;
    const size_t idx = impl.m_themeCallbacks.size();
    impl.m_themeCallbacks.push_back(std::move(callback));
    impl.m_themeCallbackIds[id] = idx;
    return id;
}

uint64_t SettingsManager::RegisterLanguageChangeCallback(LanguageChangeCallback callback) {
    auto& impl = *m_impl;
    if (!callback) return 0;
    std::unique_lock lock(impl.m_mutex);
    const uint64_t id = impl.m_nextCallbackId++;
    const size_t idx = impl.m_languageCallbacks.size();
    impl.m_languageCallbacks.push_back(std::move(callback));
    impl.m_languageCallbackIds[id] = idx;
    return id;
}

void SettingsManager::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_errorCallback = std::move(callback);
}

void SettingsManager::UnregisterCallback(uint64_t callbackId) {
    auto& impl = *m_impl;
    std::unique_lock lock(impl.m_mutex);

    // Check change callbacks
    if (impl.m_changeCallbacks.erase(callbackId) > 0) return;

    // Check theme callbacks
    auto tit = impl.m_themeCallbackIds.find(callbackId);
    if (tit != impl.m_themeCallbackIds.end()) {
        if (tit->second < impl.m_themeCallbacks.size()) {
            impl.m_themeCallbacks[tit->second] = nullptr;
        }
        impl.m_themeCallbackIds.erase(tit);
        return;
    }

    // Check language callbacks
    auto lit = impl.m_languageCallbackIds.find(callbackId);
    if (lit != impl.m_languageCallbackIds.end()) {
        if (lit->second < impl.m_languageCallbacks.size()) {
            impl.m_languageCallbacks[lit->second] = nullptr;
        }
        impl.m_languageCallbackIds.erase(lit);
        return;
    }

    SS_LOG_DEBUG(LOG_CAT, L"UnregisterCallback: ID %llu not found", callbackId);
}

// ============================================================================
// STATISTICS
// ============================================================================

SettingsStatistics SettingsManager::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void SettingsManager::ResetStatistics() {
    m_impl->m_stats.Reset();
    SS_LOG_INFO(LOG_CAT, L"Settings statistics reset");
}

// ============================================================================
// SELF-TEST & VERSION
// ============================================================================

bool SettingsManager::SelfTest() {
    SS_LOG_INFO(LOG_CAT, L"SettingsManager self-test starting");
    bool ok = true;

    // Test 1: Default settings round-trip through JSON
    try {
        UserSettings defaults;
        defaults.keyboardShortcuts = GetDefaultShortcuts();
        defaults.lastModified = std::chrono::system_clock::now();

        const Json j = UserSettingsToObj(defaults);
        const UserSettings restored = UserSettingsFromObj(j);

        if (restored.theme.theme != defaults.theme.theme) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: theme round-trip mismatch");
            ok = false;
        }
        if (restored.localization.languageCode != defaults.localization.languageCode) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: language round-trip mismatch");
            ok = false;
        }
        if (restored.notifications.enabled != defaults.notifications.enabled) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: notifications round-trip mismatch");
            ok = false;
        }
        if (restored.settingsVersion != defaults.settingsVersion) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: version round-trip mismatch");
            ok = false;
        }
        if (restored.startup.startWithWindows != defaults.startup.startWithWindows) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: startup round-trip mismatch");
            ok = false;
        }
        if (restored.window.windowWidth != defaults.window.windowWidth) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: window round-trip mismatch");
            ok = false;
        }
        if (restored.keyboardShortcuts.size() != defaults.keyboardShortcuts.size()) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: shortcuts round-trip mismatch");
            ok = false;
        }
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: exception during round-trip: %hs", ex.what());
        ok = false;
    }

    // Test 2: Validation
    {
        UserSettings invalid;
        invalid.theme.fontScale = 99.0f;
        if (invalid.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: invalid fontScale not detected");
            ok = false;
        }
    }

    // Test 3: Enum name lookups
    if (GetThemeName(Theme::Dark).empty()) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: GetThemeName returned empty");
        ok = false;
    }
    if (GetAccentColorName(AccentColor::Blue).empty()) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test FAIL: GetAccentColorName returned empty");
        ok = false;
    }

    SS_LOG_INFO(LOG_CAT, L"SettingsManager self-test %ls", ok ? L"PASSED" : L"FAILED");
    return ok;
}

std::string SettingsManager::GetVersionString() noexcept {
    try {
        return std::to_string(SettingsConstants::VERSION_MAJOR) + "."
             + std::to_string(SettingsConstants::VERSION_MINOR) + "."
             + std::to_string(SettingsConstants::VERSION_PATCH);
    }
    catch (...) { return "0.0.0"; }
}

// ============================================================================
// FREE UTILITY FUNCTIONS
// ============================================================================

std::string_view GetThemeName(Theme theme) noexcept {
    switch (theme) {
        case Theme::Light:        return "Light";
        case Theme::Dark:         return "Dark";
        case Theme::System:       return "System";
        case Theme::HighContrast: return "HighContrast";
        case Theme::Custom:       return "Custom";
    }
    return "Unknown";
}

std::string_view GetAccentColorName(AccentColor accent) noexcept {
    switch (accent) {
        case AccentColor::Blue:   return "Blue";
        case AccentColor::Green:  return "Green";
        case AccentColor::Red:    return "Red";
        case AccentColor::Orange: return "Orange";
        case AccentColor::Purple: return "Purple";
        case AccentColor::Teal:   return "Teal";
        case AccentColor::Pink:   return "Pink";
        case AccentColor::Gray:   return "Gray";
        case AccentColor::System: return "System";
        case AccentColor::Custom: return "Custom";
    }
    return "Unknown";
}

std::string_view GetTrayBehaviorName(TrayIconBehavior behavior) noexcept {
    switch (behavior) {
        case TrayIconBehavior::AlwaysShow:     return "AlwaysShow";
        case TrayIconBehavior::HideWhenClean:  return "HideWhenClean";
        case TrayIconBehavior::HideAlways:     return "HideAlways";
        case TrayIconBehavior::ShowOnActivity: return "ShowOnActivity";
    }
    return "Unknown";
}

std::string_view GetNotificationLevelName(NotificationLevel level) noexcept {
    switch (level) {
        case NotificationLevel::All:       return "All";
        case NotificationLevel::Important: return "Important";
        case NotificationLevel::Critical:  return "Critical";
        case NotificationLevel::None:      return "None";
    }
    return "Unknown";
}

std::string_view GetDateFormatName(DateFormat format) noexcept {
    switch (format) {
        case DateFormat::System:     return "System";
        case DateFormat::YYYY_MM_DD: return "YYYY-MM-DD";
        case DateFormat::DD_MM_YYYY: return "DD/MM/YYYY";
        case DateFormat::MM_DD_YYYY: return "MM/DD/YYYY";
        case DateFormat::Relative:   return "Relative";
    }
    return "Unknown";
}

std::string_view GetTimeFormatName(TimeFormat format) noexcept {
    switch (format) {
        case TimeFormat::System: return "System";
        case TimeFormat::Hour24: return "24-Hour";
        case TimeFormat::Hour12: return "12-Hour";
    }
    return "Unknown";
}

std::string FormatDate(const SystemTimePoint& time, DateFormat format) {
    const auto tt = std::chrono::system_clock::to_time_t(time);
    struct tm tmBuf{};
    gmtime_s(&tmBuf, &tt);

    char buf[64]{};
    switch (format) {
        case DateFormat::YYYY_MM_DD:
            std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                          tmBuf.tm_year + 1900, tmBuf.tm_mon + 1, tmBuf.tm_mday);
            break;
        case DateFormat::DD_MM_YYYY:
            std::snprintf(buf, sizeof(buf), "%02d/%02d/%04d",
                          tmBuf.tm_mday, tmBuf.tm_mon + 1, tmBuf.tm_year + 1900);
            break;
        case DateFormat::MM_DD_YYYY:
            std::snprintf(buf, sizeof(buf), "%02d/%02d/%04d",
                          tmBuf.tm_mon + 1, tmBuf.tm_mday, tmBuf.tm_year + 1900);
            break;
        case DateFormat::Relative: {
            const auto now = std::chrono::system_clock::now();
            const auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - time).count();
            if (diff < 60)        return std::to_string(diff) + " seconds ago";
            if (diff < 3600)      return std::to_string(diff / 60) + " minutes ago";
            if (diff < 86400)     return std::to_string(diff / 3600) + " hours ago";
            if (diff < 2592000)   return std::to_string(diff / 86400) + " days ago";
            // Fall through to system format for very old dates
            [[fallthrough]];
        }
        case DateFormat::System:
        default:
            std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                          tmBuf.tm_year + 1900, tmBuf.tm_mon + 1, tmBuf.tm_mday);
            break;
    }
    return buf;
}

std::string FormatTime(const SystemTimePoint& time, TimeFormat format) {
    const auto tt = std::chrono::system_clock::to_time_t(time);
    struct tm tmBuf{};
    gmtime_s(&tmBuf, &tt);

    char buf[64]{};
    switch (format) {
        case TimeFormat::Hour24:
            std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
                          tmBuf.tm_hour, tmBuf.tm_min, tmBuf.tm_sec);
            break;
        case TimeFormat::Hour12: {
            int hour12 = tmBuf.tm_hour % 12;
            if (hour12 == 0) hour12 = 12;
            const char* ampm = (tmBuf.tm_hour < 12) ? "AM" : "PM";
            std::snprintf(buf, sizeof(buf), "%d:%02d:%02d %s",
                          hour12, tmBuf.tm_min, tmBuf.tm_sec, ampm);
            break;
        }
        case TimeFormat::System:
        default:
            std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
                          tmBuf.tm_hour, tmBuf.tm_min, tmBuf.tm_sec);
            break;
    }
    return buf;
}

Theme GetSystemTheme() {
    RegKeyGuard guard;
    if (::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_READ, &guard.key) != ERROR_SUCCESS) {
        return Theme::Light; // Safe default
    }

    DWORD value = 1;
    DWORD size = sizeof(value);
    DWORD type = REG_DWORD;
    ::RegQueryValueExW(guard.key, L"AppsUseLightTheme", nullptr, &type,
                       reinterpret_cast<BYTE*>(&value), &size);

    return (value == 0) ? Theme::Dark : Theme::Light;
}

std::string GetSystemLanguage() {
    wchar_t locale[LOCALE_NAME_MAX_LENGTH]{};
    const int len = ::GetUserDefaultLocaleName(locale, LOCALE_NAME_MAX_LENGTH);
    if (len > 0) {
        return WideToUtf8(std::wstring_view(locale, static_cast<size_t>(len - 1)));
    }
    return "en-US";
}

}  // namespace Config
}  // namespace ShadowStrike
