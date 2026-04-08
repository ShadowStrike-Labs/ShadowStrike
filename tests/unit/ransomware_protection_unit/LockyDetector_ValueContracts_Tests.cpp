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
 * @file LockyDetector_ValueContracts_Tests.cpp
 * @brief Value-contract coverage for Ransomware::LockyDetector.
 */

#include "pch.h"

#include "../../../src/Shared_modules/RansomwareProtection/LockyDetector.hpp"

namespace {

using namespace ShadowStrike::Ransomware;
using ::testing::HasSubstr;

TEST(LockyDetectorValueContractTests, ConfigStatisticsHelpersAndVersionRemainStable) {
    LockyDetectorConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidWindow = config;
    invalidWindow.correlationWindowSecs = 0;
    EXPECT_FALSE(invalidWindow.IsValid());

    auto invalidWindowHigh = config;
    invalidWindowHigh.correlationWindowSecs = 3601;
    EXPECT_FALSE(invalidWindowHigh.IsValid());

    auto invalidRenameThreshold = config;
    invalidRenameThreshold.massRenameThreshold = 0;
    EXPECT_FALSE(invalidRenameThreshold.IsValid());

    auto invalidWriteThreshold = config;
    invalidWriteThreshold.massWriteThreshold = 0;
    EXPECT_FALSE(invalidWriteThreshold.IsValid());

    auto invalidScoreRange = config;
    invalidScoreRange.scoreBlockThreshold = invalidScoreRange.scoreAlertThreshold - 1.0;
    EXPECT_FALSE(invalidScoreRange.IsValid());

    auto invalidAlertThreshold = config;
    invalidAlertThreshold.scoreAlertThreshold = 200.1;
    EXPECT_FALSE(invalidAlertThreshold.IsValid());

    auto equalThresholds = config;
    equalThresholds.scoreBlockThreshold = equalThresholds.scoreAlertThreshold;
    EXPECT_TRUE(equalThresholds.IsValid());

    LockyStatistics stats;
    stats.totalDetections.store(2, std::memory_order_relaxed);
    stats.processesTerminated.store(1, std::memory_order_relaxed);
    stats.byVariant[static_cast<size_t>(LockyVariant::Zepto)].store(
        3, std::memory_order_relaxed);
    EXPECT_THAT(stats.ToJson(), HasSubstr("Zepto"));
    stats.Reset();

    EXPECT_EQ(stats.totalDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesTerminated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(
        stats.byVariant[static_cast<size_t>(LockyVariant::Zepto)].load(std::memory_order_relaxed),
        0u);

    LockyDetectionResult result;
    result.detected = true;
    result.variant = LockyVariant::Thor;
    result.confidence = DetectionConfidence::High;
    result.pid = 77;
    result.processName = L"locker.exe";
    result.indicators = {"mass-rename"};
    result.extensionsObserved = {L".thor"};
    result.ransomNotesFound = {L"_WHAT_is.bmp"};
    result.c2Domains = {"c2.example"};
    result.filesEncrypted = 9;
    result.score = 87.5;
    EXPECT_THAT(result.ToJson(), HasSubstr("\"variant\":\"Thor\""));
    EXPECT_THAT(result.ToJson(), HasSubstr("\"processName\":\"locker.exe\""));

    LockyStatisticsSnapshot snapshot;
    snapshot.totalDetections = 4;
    snapshot.processesTerminated = 1;
    snapshot.byVariant[static_cast<size_t>(LockyVariant::Zepto)] = 2;
    snapshot.uptimeSeconds = 7;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"variant\":\"Zepto\""));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"uptimeSeconds\":7"));

    EXPECT_EQ(GetLockyVariantName(LockyVariant::Original), "Original (.locky)");
    EXPECT_EQ(GetLockyVariantName(LockyVariant::Lukitus), "Lukitus");
    EXPECT_EQ(GetDetectionConfidenceName(DetectionConfidence::Confirmed), "Confirmed");
    EXPECT_EQ(GetDetectionConfidenceName(static_cast<DetectionConfidence>(0xFF)), "None");
    EXPECT_EQ(GetLockyExtension(LockyVariant::Thor), L".thor");
    EXPECT_EQ(GetLockyExtension(LockyVariant::Ykcol), L".ykcol");
    EXPECT_EQ(GetLockyVariantName(static_cast<LockyVariant>(0xFF)), "Unknown");
    EXPECT_TRUE(GetLockyExtension(static_cast<LockyVariant>(0xFF)).empty());
    EXPECT_EQ(LockyDetector::GetVersionString(), "3.1.0");
}

}  // namespace
