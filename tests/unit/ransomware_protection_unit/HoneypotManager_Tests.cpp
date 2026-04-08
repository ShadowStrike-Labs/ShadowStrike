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
 * @file HoneypotManager_Tests.cpp
 * @brief Comprehensive GTest coverage for Ransomware::HoneypotManager.
 *
 * Coverage focus:
 * - configuration validation, default loaders, statistics reset, helper mappings, and versioning
 * - decoy deployment, lookup, directory indexing, and removal on real temp directories
 * - integrity verification, regeneration of missing traps, and access-event recording
 * - callback delivery, false-positive marking, and kernel-notification blocking policy
 */

#include "pch.h"

#include "RansomwareProtection_TestUtils.hpp"
#include "../../../src/Shared_modules/RansomwareProtection/HoneypotManager.hpp"

#include <future>

namespace {

using namespace ShadowStrike::Ransomware;
using namespace ShadowStrike::Tests::RansomwareProtection;
using ::testing::HasSubstr;

HoneypotTemplate MakeTextTemplate(std::wstring_view filename) {
    HoneypotTemplate tmpl;
    tmpl.templateName = "UnitTestText";
    tmpl.fileType = HoneypotFileType::Text;
    tmpl.filenamePatterns = { std::wstring(filename) };
    tmpl.extension = L".txt";
    tmpl.contentTemplate = Bytes("shadowstrike-honeypot");
    tmpl.minSize = HoneypotConstants::MIN_HONEYPOT_SIZE;
    tmpl.maxSize = HoneypotConstants::MIN_HONEYPOT_SIZE;
    tmpl.randomizeContent = false;
    return tmpl;
}

class HoneypotManagerTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();

        auto& manager = HoneypotManager::Instance();
        manager.Shutdown();
        manager.ResetStatistics();

        HoneypotManagerConfiguration config;
        config.autoDeployOnStartup = false;
        config.autoRegenerate = true;
        config.hideFiles = false;
        config.makeSystemFiles = false;
        config.killOnAccess = false;
        config.maxTotalHoneypots = 32;
        config.locations.clear();
        config.templates.clear();
        ASSERT_TRUE(manager.Initialize(config));
    }

    void TearDown() override {
        auto& manager = HoneypotManager::Instance();
        manager.SetAccessCallback(nullptr);
        manager.SetStatusCallback(nullptr);
        manager.RemoveTraps();
        manager.Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(HoneypotManagerValueTests, ConfigurationDefaultsStatisticsUtilitiesAndVersionRemainStable) {
    HoneypotManagerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidZero = config;
    invalidZero.maxTotalHoneypots = 0;
    EXPECT_FALSE(invalidZero.IsValid());

    auto invalidHigh = config;
    invalidHigh.maxTotalHoneypots = 10001;
    EXPECT_FALSE(invalidHigh.IsValid());

    HoneypotManagerConfiguration defaults;
    defaults.LoadDefaultLocations();
    ASSERT_EQ(defaults.locations.size(), 4u);
    EXPECT_EQ(defaults.locations[0].type, LocationType::UserDocuments);
    EXPECT_EQ(defaults.locations[0].priority, 10u);
    EXPECT_EQ(defaults.locations[1].type, LocationType::UserDesktop);
    EXPECT_EQ(defaults.locations[2].type, LocationType::UserDownloads);
    EXPECT_EQ(defaults.locations[3].type, LocationType::UserPictures);

    HoneypotManagerConfiguration templateConfig;
    templateConfig.LoadDefaultTemplates();
    ASSERT_EQ(templateConfig.templates.size(), 4u);
    EXPECT_EQ(templateConfig.templates[0].fileType, HoneypotFileType::Document);
    EXPECT_EQ(templateConfig.templates[1].fileType, HoneypotFileType::PDF);
    EXPECT_EQ(templateConfig.templates[2].fileType, HoneypotFileType::Spreadsheet);
    EXPECT_EQ(templateConfig.templates[3].fileType, HoneypotFileType::Image);

    HoneypotStatistics stats;
    stats.totalDeployed.store(3, std::memory_order_relaxed);
    stats.currentlyActive.store(2, std::memory_order_relaxed);
    stats.accessEvents.store(5, std::memory_order_relaxed);
    stats.processesKilled.store(1, std::memory_order_relaxed);
    stats.regenerations.store(4, std::memory_order_relaxed);
    stats.falsePositives.store(6, std::memory_order_relaxed);
    stats.eventsByType[static_cast<size_t>(HoneypotAccessType::Write)].store(
        7, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.totalDeployed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.currentlyActive.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.accessEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesKilled.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.regenerations.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.falsePositives.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(
        stats.eventsByType[static_cast<size_t>(HoneypotAccessType::Write)].load(
            std::memory_order_relaxed),
        0u);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"totalDeployed\":0"));

    EXPECT_EQ(GetHoneypotTypeName(HoneypotType::Shortcut), "Shortcut");
    EXPECT_EQ(GetHoneypotFileTypeName(HoneypotFileType::Document), "Document");
    EXPECT_EQ(GetHoneypotFileTypeName(HoneypotFileType::Text), "Other");
    EXPECT_EQ(GetLocationTypeName(LocationType::Custom), "Custom");
    EXPECT_EQ(GetAccessTypeName(HoneypotAccessType::Rename), "Rename");
    EXPECT_EQ(GetHoneypotStatusName(HoneypotStatus::Compromised), "Compromised");

    const auto defaultTemplate = GetDefaultTemplate(HoneypotFileType::Document);
    EXPECT_FALSE(defaultTemplate.extension.empty());
    EXPECT_GE(defaultTemplate.minSize, HoneypotConstants::MIN_HONEYPOT_SIZE);

    EXPECT_EQ(HoneypotManager::GetVersionString(), "3.1.0");
}

TEST_F(HoneypotManagerTest, DeploySingleTrapIndexesPathAndRemoveByPathCleansState) {
    auto& manager = HoneypotManager::Instance();
    const auto targetDir = CreateDirectory(L"decoys");

    const auto honeypotId = manager.DeployHoneypot(targetDir.wstring(), MakeTextTemplate(L"budget.txt"));
    ASSERT_TRUE(honeypotId.has_value());

    const auto honeypot = manager.GetHoneypotById(*honeypotId);
    ASSERT_TRUE(honeypot.has_value());
    EXPECT_TRUE(std::filesystem::exists(honeypot->path));
    EXPECT_TRUE(manager.IsTrap(honeypot->path));

    const auto byPath = manager.GetHoneypot(honeypot->path);
    ASSERT_TRUE(byPath.has_value());
    EXPECT_EQ(byPath->honeypotId, *honeypotId);

    EXPECT_EQ(manager.GetHoneypotCount(), 1u);
    EXPECT_EQ(manager.GetActiveHoneypotCount(), 1u);
    EXPECT_EQ(manager.GetActiveHoneypots().size(), 1u);
    EXPECT_EQ(manager.GetHoneypotsInDirectory(targetDir.wstring()).size(), 1u);

    manager.RemoveHoneypotByPath(honeypot->path);

    EXPECT_FALSE(std::filesystem::exists(honeypot->path));
    EXPECT_FALSE(manager.IsTrap(honeypot->path));
    EXPECT_EQ(manager.GetHoneypotCount(), 0u);
    EXPECT_EQ(manager.GetActiveHoneypotCount(), 0u);
}

TEST_F(HoneypotManagerTest, VerifyMissingTrapAndRegenerateTrapRestoreHealthyState) {
    auto& manager = HoneypotManager::Instance();
    const auto targetDir = CreateDirectory(L"regen");

    const auto honeypotId =
        manager.DeployHoneypot(targetDir.wstring(), MakeTextTemplate(L"report.txt"));
    ASSERT_TRUE(honeypotId.has_value());

    auto honeypot = manager.GetHoneypotById(*honeypotId);
    ASSERT_TRUE(honeypot.has_value());
    const auto honeypotPath = std::filesystem::path(honeypot->path);

    std::error_code ec;
    std::filesystem::remove(honeypotPath, ec);
    ASSERT_FALSE(ec);

    EXPECT_FALSE(manager.VerifyHoneypot(*honeypotId));
    honeypot = manager.GetHoneypotById(*honeypotId);
    ASSERT_TRUE(honeypot.has_value());
    EXPECT_EQ(honeypot->status, HoneypotStatus::Missing);

    manager.RegenerateTrap(*honeypotId);

    EXPECT_TRUE(std::filesystem::exists(honeypotPath));
    honeypot = manager.GetHoneypotById(*honeypotId);
    ASSERT_TRUE(honeypot.has_value());
    EXPECT_EQ(honeypot->status, HoneypotStatus::Active);
    EXPECT_EQ(manager.GetStatistics().regenerations, 1u);
}

TEST_F(HoneypotManagerTest, AccessCallbacksFalsePositiveFlowAndKernelVerdictsAreDeterministic) {
    auto& manager = HoneypotManager::Instance();
    const auto targetDir = CreateDirectory(L"access");

    const auto honeypotId =
        manager.DeployHoneypot(targetDir.wstring(), MakeTextTemplate(L"access.txt"));
    ASSERT_TRUE(honeypotId.has_value());

    const auto honeypot = manager.GetHoneypotById(*honeypotId);
    ASSERT_TRUE(honeypot.has_value());

    std::promise<HoneypotAccessEvent> accessPromise;
    auto accessFuture = accessPromise.get_future();
    std::atomic<bool> accessDelivered{ false };
    manager.SetAccessCallback(
        [&](const HoneypotAccessEvent& event) {
            if (!accessDelivered.exchange(true)) {
                accessPromise.set_value(event);
            }
        });

    manager.OnHoneypotAccessed(honeypot->path, 5303, HoneypotAccessType::Write);

    ASSERT_EQ(accessFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const auto event = accessFuture.get();
    EXPECT_EQ(event.honeypotId, *honeypotId);
    EXPECT_EQ(event.honeypotPath, honeypot->path);
    EXPECT_EQ(event.accessType, HoneypotAccessType::Write);

    const auto recentEvents = manager.GetRecentAccessEvents(1);
    ASSERT_EQ(recentEvents.size(), 1u);
    EXPECT_TRUE(recentEvents.front().isSuspicious);

    const auto statsAfterAccess = manager.GetStatistics();
    EXPECT_EQ(statsAfterAccess.accessEvents, 1u);
    EXPECT_EQ(statsAfterAccess.eventsByType[static_cast<size_t>(HoneypotAccessType::Write)], 1u);

    manager.ReportFalsePositive(event.eventId, "expected unit-test access");

    const auto updatedEvents = manager.GetRecentAccessEvents(1);
    ASSERT_EQ(updatedEvents.size(), 1u);
    EXPECT_FALSE(updatedEvents.front().isSuspicious);
    EXPECT_THAT(updatedEvents.front().details, HasSubstr(L"False Positive"));
    EXPECT_EQ(manager.GetStatistics().falsePositives, 1u);

    EXPECT_TRUE(manager.ProcessKernelNotification(
        honeypot->path, 5303, 1, HoneypotAccessType::Write));
    EXPECT_FALSE(manager.ProcessKernelNotification(
        honeypot->path, 5303, 2, HoneypotAccessType::Read));
}

}  // namespace
