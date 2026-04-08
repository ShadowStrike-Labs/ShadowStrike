#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Communication/NotificationManager.hpp"

#include <chrono>
#include <string>

namespace Notify = ShadowStrike::Communication;

namespace {

using SystemClock = std::chrono::system_clock;

SystemClock::time_point FixedTime() {
    return SystemClock::from_time_t(1'700'000'000);
}

} // namespace

/*
 * ============================================================================
 * ShadowStrike NotificationManager - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - User-visible notification serialization
 * - Quiet-hours / preference validation guards
 * - Statistics snapshot behavior for diagnostics
 *
 * ============================================================================
 */

TEST(NotificationManagerTest, NotificationModelsSerializeImportantUserFacingFields) {
    Notify::NotificationButton button{};
    button.buttonId = "restore";
    button.text = L"Restore";
    button.style = Notify::ButtonStyle::Primary;
    button.action = "restore";
    button.arguments = "item=42";
    button.isDismiss = false;

    const std::string buttonJson = button.ToJson();
    EXPECT_NE(buttonJson.find("\"buttonId\":\"restore\""), std::string::npos);
    EXPECT_NE(buttonJson.find("\"action\":\"restore\""), std::string::npos);

    Notify::Notification notification{};
    notification.notificationId = "notif-1";
    notification.level = Notify::NotificationLevel::Warning;
    notification.type = Notify::NotificationType::Toast;
    notification.category = Notify::NotificationCategory::ThreatDetection;
    notification.title = L"Threat blocked";
    notification.message = L"Suspicious executable blocked";
    notification.priority = 7;
    notification.bypassQuietMode = true;
    notification.tag = "threat";
    notification.group = "security";
    notification.createdTime = FixedTime();
    notification.shownTime = FixedTime();
    notification.buttons.push_back(button);
    notification.data["threat"] = "Trojan.Test";

    const std::string notificationJson = notification.ToJson();
    EXPECT_NE(notificationJson.find("\"notificationId\":\"notif-1\""), std::string::npos);
    EXPECT_NE(notificationJson.find("\"priority\":7"), std::string::npos);
    EXPECT_NE(notificationJson.find("\"bypassQuietMode\":true"), std::string::npos);
    EXPECT_NE(notificationJson.find("\"buttons\":"), std::string::npos);
    EXPECT_NE(notificationJson.find("\"threat\":\"Trojan.Test\""), std::string::npos);

    Notify::ThreatNotification threat{};
    threat.threatName = L"Trojan.Test";
    threat.filePath = LR"(C:\Temp\bad.exe)";
    threat.threatType = L"Trojan";
    threat.severity = L"High";
    threat.actionTaken = L"Quarantined";
    threat.showRestoreButton = true;
    threat.showDetailsButton = false;

    const std::string threatJson = threat.ToJson();
    EXPECT_NE(threatJson.find("\"showRestoreButton\":true"), std::string::npos);
    EXPECT_NE(threatJson.find("\"showDetailsButton\":false"), std::string::npos);
}

TEST(NotificationManagerTest, NotificationPreferencesValidateVolumeAndConcurrencyBounds) {
    Notify::NotificationPreferences preferences{};
    EXPECT_TRUE(preferences.IsValid());

    preferences.soundVolume = 0;
    preferences.maxConcurrent = 20;
    EXPECT_TRUE(preferences.IsValid());

    preferences.soundVolume = 100;
    EXPECT_TRUE(preferences.IsValid());

    preferences.soundVolume = -1;
    EXPECT_FALSE(preferences.IsValid());

    preferences = {};
    preferences.soundVolume = 101;
    EXPECT_FALSE(preferences.IsValid());

    preferences = {};
    preferences.maxConcurrent = 0;
    EXPECT_FALSE(preferences.IsValid());

    preferences = {};
    preferences.maxConcurrent = 21;
    EXPECT_FALSE(preferences.IsValid());
}

TEST(NotificationManagerTest, QuietHoursScheduleReturnsFalseForDisabledOrImpossibleSchedules) {
    Notify::QuietHoursSchedule quietHours{};
    quietHours.enabled = false;
    EXPECT_FALSE(quietHours.IsActive());

    quietHours.enabled = true;
    quietHours.daysOfWeek = 0;
    EXPECT_FALSE(quietHours.IsActive());

    quietHours.daysOfWeek = 0x7F;
    quietHours.startHour = 9;
    quietHours.startMinute = 30;
    quietHours.endHour = 9;
    quietHours.endMinute = 30;
    EXPECT_FALSE(quietHours.IsActive());
}

TEST(NotificationManagerTest, NotificationConfigurationRejectsUnsafeRateLimitsAndTraversal) {
    Notify::NotificationConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.rateLimitPerMinute = 1000;
    config.dedupWindowSeconds = 3600;
    config.quietHours.enabled = true;
    config.quietHours.startHour = 23;
    config.quietHours.startMinute = 59;
    config.quietHours.endHour = 0;
    config.quietHours.endMinute = 0;
    config.customSoundsFolder = LR"(C:\Sounds)";
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.rateLimitPerMinute = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.rateLimitPerMinute = 1001;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.dedupWindowSeconds = 3601;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.quietHours.enabled = true;
    config.quietHours.startHour = 24;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.quietHours.enabled = true;
    config.quietHours.endMinute = 60;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.customSoundsFolder = LR"(C:\Sounds\..\Escapes)";
    EXPECT_FALSE(config.IsValid());
}

TEST(NotificationManagerTest, NotificationStatisticsResetProducesAccurateSnapshotAndJson) {
    Notify::NotificationStatistics stats{};
    stats.totalShown.store(10, std::memory_order_relaxed);
    stats.totalClicked.store(2, std::memory_order_relaxed);
    stats.totalDismissed.store(1, std::memory_order_relaxed);
    stats.totalExpired.store(3, std::memory_order_relaxed);
    stats.totalSuppressed.store(4, std::memory_order_relaxed);
    stats.totalFailed.store(5, std::memory_order_relaxed);
    stats.totalButtonClicks.store(6, std::memory_order_relaxed);
    stats.rateLimitHits.store(7, std::memory_order_relaxed);
    stats.quietModeSuppressions.store(8, std::memory_order_relaxed);
    stats.byLevel[1].store(9, std::memory_order_relaxed);
    stats.byCategory[2].store(10, std::memory_order_relaxed);

    Notify::NotificationStatisticsSnapshot snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.totalShown, 10u);
    EXPECT_EQ(snapshot.quietModeSuppressions, 8u);
    EXPECT_EQ(snapshot.byLevel[1], 9u);
    EXPECT_EQ(snapshot.byCategory[2], 10u);
    EXPECT_NE(snapshot.ToJson().find("\"rateLimitHits\":7"), std::string::npos);

    stats.Reset();
    snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.totalShown, 0u);
    EXPECT_EQ(snapshot.totalFailed, 0u);
    EXPECT_EQ(snapshot.byLevel[1], 0u);
}
