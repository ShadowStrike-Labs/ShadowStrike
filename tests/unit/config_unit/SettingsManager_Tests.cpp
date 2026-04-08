/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Comprehensive unit coverage for user settings management.
 *
 * Focus:
 *   - settings/configuration validation and serialization
 *   - load/save/export/import behavior and JSON normalization
 *   - mutation APIs, callbacks, formatting helpers, and statistics
 */

#include "pch.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include "../../../src/Shared_modules/Config/SettingsManager.hpp"
#include "Config_TestUtils.hpp"

namespace ShadowStrike::Config::Test {

class SettingsManagerTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_SettingsTests_"};
    SettingsManager& manager = SettingsManager::Instance();

    void SetUp() override {
        manager.Shutdown();

        SettingsManagerConfiguration config;
        config.settingsFilePath = tempDir.File(L"user-settings.json");
        config.enableAutoSave = false;
        config.createBackupOnSave = false;
        ASSERT_TRUE(manager.Initialize(config));
        manager.ResetStatistics();
    }

    void TearDown() override {
        manager.Shutdown();
    }
};

TEST_F(SettingsManagerTest, ConfigurationSerializationAndUtilityContractsRemainStable) {
    SettingsManagerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.autoSaveIntervalSeconds = 4;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxBackups = 101;
    EXPECT_FALSE(config.IsValid());

    ThemeSettings theme;
    theme.theme = Theme::Custom;
    theme.accent = AccentColor::Purple;
    theme.customAccentRgb = 0x112233;
    theme.fontScale = 1.25f;
    const auto themeJson = ParseJson(theme.ToJson());
    EXPECT_EQ(themeJson.at("theme").get<uint8_t>(), static_cast<uint8_t>(Theme::Custom));
    EXPECT_EQ(themeJson.at("accent").get<uint8_t>(), static_cast<uint8_t>(AccentColor::Purple));
    EXPECT_FLOAT_EQ(themeJson.at("fontScale").get<float>(), 1.25f);

    LocalizationSettings localization;
    localization.languageCode = "tr-TR";
    localization.dateFormat = DateFormat::DD_MM_YYYY;
    localization.timeFormat = TimeFormat::Hour12;
    const auto localizationJson = ParseJson(localization.ToJson());
    EXPECT_EQ(localizationJson.at("languageCode").get<std::string>(), "tr-TR");
    EXPECT_EQ(localizationJson.at("dateFormat").get<uint8_t>(), static_cast<uint8_t>(DateFormat::DD_MM_YYYY));

    NotificationSettings notifications;
    notifications.enabled = false;
    notifications.level = NotificationLevel::Critical;
    notifications.doNotDisturbEnabled = true;
    const auto notificationJson = ParseJson(notifications.ToJson());
    EXPECT_FALSE(notificationJson.at("enabled").get<bool>());
    EXPECT_EQ(notificationJson.at("level").get<uint8_t>(), static_cast<uint8_t>(NotificationLevel::Critical));

    StartupSettings startup;
    startup.startMinimized = true;
    startup.trayBehavior = TrayIconBehavior::ShowOnActivity;
    const auto startupJson = ParseJson(startup.ToJson());
    EXPECT_TRUE(startupJson.at("startMinimized").get<bool>());
    EXPECT_EQ(startupJson.at("trayBehavior").get<uint8_t>(), static_cast<uint8_t>(TrayIconBehavior::ShowOnActivity));

    AccessibilitySettings accessibility;
    accessibility.highContrastMode = true;
    accessibility.largeText = true;
    const auto accessibilityJson = ParseJson(accessibility.ToJson());
    EXPECT_TRUE(accessibilityJson.at("highContrastMode").get<bool>());
    EXPECT_TRUE(accessibilityJson.at("largeText").get<bool>());

    WindowSettings window;
    window.windowX = 400;
    window.windowWidth = 1440;
    const auto windowJson = ParseJson(window.ToJson());
    EXPECT_EQ(windowJson.at("x").get<int32_t>(), 400);
    EXPECT_EQ(windowJson.at("width").get<uint32_t>(), 1440u);

    ScanUISettings scanUi;
    scanUi.autoCloseOnClean = true;
    scanUi.defaultViewMode = "grid";
    const auto scanUiJson = ParseJson(scanUi.ToJson());
    EXPECT_TRUE(scanUiJson.at("autoCloseOnClean").get<bool>());
    EXPECT_EQ(scanUiJson.at("defaultViewMode").get<std::string>(), "grid");

    UserSettings settings;
    settings.theme = theme;
    settings.localization = localization;
    settings.notifications = notifications;
    settings.keyboardShortcuts = {{"scan", "Ctrl+S"}};
    settings.recentItems = {L"C:\\Temp\\a.txt"};
    settings.favoriteLocations = {L"C:\\Workspace"};
    settings.lastModified = std::chrono::system_clock::time_point{std::chrono::seconds(5)};
    EXPECT_TRUE(settings.IsValid());

    const auto userSettingsJson = ParseJson(settings.ToJson());
    EXPECT_EQ(userSettingsJson.at("keyboardShortcuts").at("scan").get<std::string>(), "Ctrl+S");
    EXPECT_EQ(userSettingsJson.at("recentItems").at(0).get<std::string>(), "C:\\Temp\\a.txt");

    UserSettings invalid = settings;
    invalid.theme.fontScale = 99.0f;
    EXPECT_FALSE(invalid.IsValid());
    invalid = settings;
    invalid.localization.languageCode.clear();
    EXPECT_FALSE(invalid.IsValid());
    invalid = settings;
    invalid.recentItems.assign(SettingsConstants::MAX_RECENT_FILES + 1, L"overflow");
    EXPECT_FALSE(invalid.IsValid());
    invalid = settings;
    for (size_t index = 0; index <= SettingsConstants::MAX_CUSTOM_SHORTCUTS; ++index) {
        invalid.keyboardShortcuts["action-" + std::to_string(index)] = "Ctrl+X";
    }
    EXPECT_FALSE(invalid.IsValid());

    SettingsChangeEvent changeEvent;
    changeEvent.category = "theme";
    changeEvent.key = "accent";
    changeEvent.timestamp = std::chrono::system_clock::time_point{std::chrono::seconds(10)};
    const auto changeJson = ParseJson(changeEvent.ToJson());
    EXPECT_EQ(changeJson.at("category").get<std::string>(), "theme");
    EXPECT_EQ(changeJson.at("key").get<std::string>(), "accent");

    SettingsStatistics stats;
    stats.totalLoads.store(2, std::memory_order_relaxed);
    stats.totalSaves.store(3, std::memory_order_relaxed);
    stats.settingChanges.store(4, std::memory_order_relaxed);
    const auto statsJson = ParseJson(stats.ToJson());
    EXPECT_EQ(statsJson.at("totalLoads").get<uint64_t>(), 2u);
    EXPECT_EQ(statsJson.at("totalSaves").get<uint64_t>(), 3u);
    EXPECT_EQ(statsJson.at("settingChanges").get<uint64_t>(), 4u);
    stats.Reset();
    EXPECT_EQ(ParseJson(stats.ToJson()).at("totalLoads").get<uint64_t>(), 0u);

    EXPECT_EQ(GetThemeName(Theme::HighContrast), "HighContrast");
    EXPECT_EQ(GetAccentColorName(AccentColor::System), "System");
    EXPECT_EQ(GetTrayBehaviorName(TrayIconBehavior::HideWhenClean), "HideWhenClean");
    EXPECT_EQ(GetNotificationLevelName(NotificationLevel::Important), "Important");
    EXPECT_EQ(GetDateFormatName(DateFormat::MM_DD_YYYY), "MM/DD/YYYY");
    EXPECT_EQ(GetTimeFormatName(TimeFormat::Hour12), "12-Hour");

    const auto sampleTime = std::chrono::system_clock::time_point{
        std::chrono::seconds(1712577600)};  // 2024-04-08T12:00:00Z
    EXPECT_EQ(FormatDate(sampleTime, DateFormat::YYYY_MM_DD), "2024-04-08");
    EXPECT_EQ(FormatDate(sampleTime, DateFormat::DD_MM_YYYY), "08/04/2024");
    EXPECT_EQ(FormatDate(sampleTime, DateFormat::MM_DD_YYYY), "04/08/2024");
    EXPECT_EQ(FormatTime(sampleTime, TimeFormat::Hour24), "12:00:00");
    EXPECT_EQ(FormatTime(sampleTime, TimeFormat::Hour12), "12:00:00 PM");
    EXPECT_THAT(FormatDate(std::chrono::system_clock::now() - std::chrono::seconds(90), DateFormat::Relative),
                ::testing::HasSubstr("minutes ago"));
    EXPECT_FALSE(GetSystemLanguage().empty());
    EXPECT_THAT(GetSystemTheme(), ::testing::AnyOf(Theme::Light, Theme::Dark));
    EXPECT_EQ(SettingsManager::GetVersionString(), "3.0.0");
    EXPECT_TRUE(manager.SelfTest());
}

TEST_F(SettingsManagerTest, LoadSaveExportImportAndResetNormalizePersistentState) {
    const auto initial = manager.GetCurrentSettings();
    EXPECT_THAT(initial.keyboardShortcuts, ::testing::Contains(::testing::Pair("scan", "Ctrl+S")));

    UserSettings modified = initial;
    modified.theme.theme = Theme::Dark;
    modified.theme.accent = AccentColor::Teal;
    modified.localization.languageCode = "tr-TR";
    modified.notifications.level = NotificationLevel::Critical;
    modified.recentItems = {L"C:\\Alpha.txt", L"C:\\Beta.txt"};
    modified.favoriteLocations = {L"C:\\Workspace"};
    modified.keyboardShortcuts["scan"] = "Ctrl+Alt+S";
    ASSERT_TRUE(manager.Save(modified));

    const auto persisted = ReadJsonFile(tempDir.File(L"user-settings.json"));
    EXPECT_EQ(persisted.at("theme").at("theme").get<uint8_t>(), static_cast<uint8_t>(Theme::Dark));
    EXPECT_EQ(persisted.at("theme").at("accent").get<uint8_t>(), static_cast<uint8_t>(AccentColor::Teal));
    EXPECT_EQ(persisted.at("localization").at("languageCode").get<std::string>(), "tr-TR");
    EXPECT_EQ(persisted.at("keyboardShortcuts").at("scan").get<std::string>(), "Ctrl+Alt+S");

    const auto reloaded = manager.Load();
    EXPECT_EQ(reloaded.localization.languageCode, "tr-TR");
    EXPECT_EQ(reloaded.theme.theme, Theme::Dark);

    ASSERT_TRUE(manager.ExportSettings(tempDir.File(L"exported-settings.json")));
    const auto exported = ReadJsonFile(tempDir.File(L"exported-settings.json"));
    EXPECT_EQ(exported.at("theme").at("theme").get<uint8_t>(), static_cast<uint8_t>(Theme::Dark));

    Json importJson = Json::object();
    importJson["version"] = 3u;
    importJson["theme"] = {
        {"theme", 99},
        {"accent", 99},
        {"customAccentRgb", 0x445566u},
        {"customThemePath", "theme.json"},
        {"enableAnimations", false},
        {"enableTransparency", false},
        {"fontScale", 9.5f}
    };
    importJson["localization"] = {
        {"languageCode", "de-DE"},
        {"dateFormat", static_cast<uint8_t>(DateFormat::MM_DD_YYYY)},
        {"timeFormat", static_cast<uint8_t>(TimeFormat::Hour24)},
        {"decimalSeparator", ","},
        {"thousandsSeparator", "."},
        {"use24HourFormat", true},
        {"firstDayOfWeek", 9}
    };
    importJson["notifications"] = {
        {"enabled", true},
        {"level", static_cast<uint8_t>(NotificationLevel::Important)},
        {"sound", static_cast<uint8_t>(SoundSetting::All)},
        {"dndStartHour", 21u},
        {"dndEndHour", 6u}
    };
    Json recentItems = Json::array();
    for (size_t index = 0; index < SettingsConstants::MAX_RECENT_FILES + 10; ++index) {
        recentItems.push_back("C:\\Recent\\" + std::to_string(index));
    }
    importJson["recentItems"] = recentItems;

    Json favorites = Json::array();
    for (size_t index = 0; index < SettingsConstants::MAX_RECENT_FILES + 5; ++index) {
        favorites.push_back("C:\\Favorite\\" + std::to_string(index));
    }
    importJson["favoriteLocations"] = favorites;
    importJson["keyboardShortcuts"] = {{"investigate", "Ctrl+Shift+I"}};
    importJson["lastModified"] = 5000;

    WriteUtf8File(tempDir.File(L"import-settings.json"), importJson.dump(2));
    ASSERT_TRUE(manager.ImportSettings(tempDir.File(L"import-settings.json")));

    const auto imported = manager.GetCurrentSettings();
    EXPECT_EQ(imported.theme.theme, Theme::System);
    EXPECT_EQ(imported.theme.accent, AccentColor::Blue);
    EXPECT_FLOAT_EQ(imported.theme.fontScale, 3.0f);
    EXPECT_EQ(imported.localization.languageCode, "de-DE");
    EXPECT_EQ(imported.localization.firstDayOfWeek, 0);
    EXPECT_EQ(imported.recentItems.size(), SettingsConstants::MAX_RECENT_FILES);
    EXPECT_EQ(imported.favoriteLocations.size(), SettingsConstants::MAX_RECENT_FILES);
    ASSERT_EQ(imported.keyboardShortcuts.size(), 1u);
    EXPECT_EQ(imported.keyboardShortcuts.at("investigate"), "Ctrl+Shift+I");

    manager.ResetToDefaults();
    const auto defaults = manager.GetCurrentSettings();
    EXPECT_EQ(defaults.theme.theme, Theme::System);
    EXPECT_THAT(defaults.keyboardShortcuts, ::testing::Contains(::testing::Pair("scan", "Ctrl+S")));

    const auto factoryDefaults = manager.GetFactoryDefaults();
    EXPECT_THAT(factoryDefaults.keyboardShortcuts, ::testing::Contains(::testing::Pair("help", "F1")));

    const auto stats = manager.GetStatistics();
    EXPECT_GE(stats.totalLoads.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(stats.totalSaves.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(stats.imports.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(stats.exports.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(stats.resets.load(std::memory_order_relaxed), 1u);
}

TEST_F(SettingsManagerTest, MutationApisAndCallbacksUpdateOnlyLocalState) {
    std::vector<SettingsChangeEvent> changeEvents;
    std::vector<Theme> themeEvents;
    std::vector<std::string> languageEvents;

    const auto changeCallbackId = manager.RegisterChangeCallback(
        [&changeEvents](const SettingsChangeEvent& event) {
            changeEvents.push_back(event);
        });
    const auto themeCallbackId = manager.RegisterThemeChangeCallback(
        [&themeEvents](const Theme theme) {
            themeEvents.push_back(theme);
        });
    const auto languageCallbackId = manager.RegisterLanguageChangeCallback(
        [&languageEvents](const std::string& language) {
            languageEvents.push_back(language);
        });

    manager.SetTheme(Theme::Dark);
    manager.SetAccentColor(AccentColor::Purple);
    manager.SetCustomAccentColor(0x336699);
    manager.SetTheme(Theme::System);
    EXPECT_THAT(manager.GetEffectiveTheme(), ::testing::AnyOf(Theme::Light, Theme::Dark));

    manager.SetLanguage("de-DE");
    manager.SetLanguage("");
    EXPECT_EQ(manager.GetLocalizationSettings().languageCode, "de-DE");
    manager.SetDateFormat(DateFormat::Relative);
    manager.SetTimeFormat(TimeFormat::Hour12);

    manager.SetNotificationLevel(NotificationLevel::Critical);
    manager.SetDoNotDisturb(true);
    manager.SetNotificationsEnabled(false);
    EXPECT_EQ(manager.GetNotificationSettings().level, NotificationLevel::Critical);
    EXPECT_TRUE(manager.GetNotificationSettings().doNotDisturbEnabled);
    EXPECT_FALSE(manager.GetNotificationSettings().enabled);

    manager.SetHighContrastMode(true);
    manager.SetLargeText(true);
    EXPECT_TRUE(manager.GetAccessibilitySettings().highContrastMode);
    EXPECT_TRUE(manager.GetAccessibilitySettings().largeText);

    WindowSettings window = manager.GetWindowSettings();
    window.rememberPosition = true;
    manager.SetWindowSettings(window);
    manager.SaveWindowPosition(10, 20, 800, 600, true);
    auto updatedWindow = manager.GetWindowSettings();
    EXPECT_EQ(updatedWindow.windowX, 10);
    EXPECT_EQ(updatedWindow.windowY, 20);
    EXPECT_EQ(updatedWindow.windowWidth, 800u);
    EXPECT_TRUE(updatedWindow.isMaximized);

    updatedWindow.rememberPosition = false;
    manager.SetWindowSettings(updatedWindow);
    manager.SaveWindowPosition(99, 88, 1200, 700, false);
    const auto frozenWindow = manager.GetWindowSettings();
    EXPECT_EQ(frozenWindow.windowX, 10);
    EXPECT_EQ(frozenWindow.windowWidth, 800u);

    manager.AddRecentItem(L"C:\\One.txt");
    manager.AddRecentItem(L"C:\\Two.txt");
    manager.AddRecentItem(L"C:\\One.txt");
    const auto recentItems = manager.GetRecentItems();
    ASSERT_EQ(recentItems.size(), 2u);
    EXPECT_EQ(recentItems.front(), L"C:\\One.txt");

    manager.ClearRecentItems();
    EXPECT_TRUE(manager.GetRecentItems().empty());

    manager.AddFavoriteLocation(L"C:\\Workspace");
    manager.AddFavoriteLocation(L"C:\\Workspace");
    ASSERT_EQ(manager.GetFavoriteLocations().size(), 1u);
    manager.RemoveFavoriteLocation(L"C:\\Workspace");
    EXPECT_TRUE(manager.GetFavoriteLocations().empty());

    manager.SetKeyboardShortcut("hunt", "Ctrl+Shift+H");
    ASSERT_EQ(manager.GetKeyboardShortcut("hunt"), std::optional<std::string>("Ctrl+Shift+H"));
    EXPECT_THAT(manager.GetAllKeyboardShortcuts(), ::testing::Contains(::testing::Pair("hunt", "Ctrl+Shift+H")));
    manager.ResetKeyboardShortcuts();
    EXPECT_FALSE(manager.GetKeyboardShortcut("hunt").has_value());
    EXPECT_EQ(manager.GetKeyboardShortcut("scan"), std::optional<std::string>("Ctrl+S"));

    UserSettings current = manager.GetCurrentSettings();
    current.scanUI.defaultViewMode = "grid";
    manager.SetCurrentSettings(current);
    EXPECT_EQ(manager.GetCurrentSettings().scanUI.defaultViewMode, "grid");

    manager.UnregisterCallback(changeCallbackId);
    manager.UnregisterCallback(themeCallbackId);
    manager.UnregisterCallback(languageCallbackId);

    EXPECT_GE(changeEvents.size(), 10u);
    EXPECT_THAT(themeEvents, ::testing::Contains(Theme::Dark));
    EXPECT_THAT(themeEvents, ::testing::Contains(Theme::HighContrast));
    EXPECT_THAT(languageEvents, ::testing::ElementsAre("de-DE"));

    const auto availableLanguages = manager.GetAvailableLanguages();
    EXPECT_THAT(availableLanguages, ::testing::Contains(std::make_pair(std::string("tr-TR"),
                                                                       std::string("Türkçe (Türkiye)"))));

    const auto stats = manager.GetStatistics();
    EXPECT_GE(stats.settingChanges.load(std::memory_order_relaxed), 10u);
}

TEST_F(SettingsManagerTest, ErrorPathsSaveCurrentAndCallbackUnregistrationHonorContracts) {
    std::vector<int> errorCodes;
    manager.RegisterErrorCallback([&errorCodes](const std::string&, const int code) {
        errorCodes.push_back(code);
    });

    UserSettings invalid = manager.GetCurrentSettings();
    invalid.localization.languageCode.clear();
    EXPECT_FALSE(manager.Save(invalid));
    EXPECT_THAT(errorCodes, ::testing::Contains(-3));

    EXPECT_FALSE(manager.ExportSettings(fs::path{}));
    EXPECT_FALSE(manager.ImportSettings(fs::path{}));

    WriteUtf8File(tempDir.File(L"user-settings.json"), "{ invalid json");
    const auto loaded = manager.Load();
    EXPECT_THAT(loaded.keyboardShortcuts, ::testing::Contains(::testing::Pair("scan", "Ctrl+S")));
    EXPECT_THAT(errorCodes, ::testing::Contains(-2));

    uint32_t themeEvents = 0;
    uint32_t languageEvents = 0;
    const auto themeCallbackId = manager.RegisterThemeChangeCallback(
        [&themeEvents](const Theme) {
            ++themeEvents;
        });
    const auto languageCallbackId = manager.RegisterLanguageChangeCallback(
        [&languageEvents](const std::string&) {
            ++languageEvents;
        });

    manager.UnregisterCallback(themeCallbackId);
    manager.UnregisterCallback(languageCallbackId);
    manager.SetTheme(Theme::Dark);
    manager.SetLanguage("fr-FR");
    EXPECT_EQ(themeEvents, 0u);
    EXPECT_EQ(languageEvents, 0u);

    manager.SetAccentColor(AccentColor::Teal);
    EXPECT_TRUE(manager.SaveCurrent());
    const auto persisted = ReadJsonFile(tempDir.File(L"user-settings.json"));
    EXPECT_TRUE(persisted.contains("lastModified"));

    const auto stats = manager.GetStatistics();
    EXPECT_GE(stats.totalSaves.load(std::memory_order_relaxed), 1u);
}

}  // namespace ShadowStrike::Config::Test
