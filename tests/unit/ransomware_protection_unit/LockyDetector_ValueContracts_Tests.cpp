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

    auto invalidRenameThreshold = config;
    invalidRenameThreshold.massRenameThreshold = 0;
    EXPECT_FALSE(invalidRenameThreshold.IsValid());

    auto invalidScoreRange = config;
    invalidScoreRange.scoreBlockThreshold = invalidScoreRange.scoreAlertThreshold - 1.0;
    EXPECT_FALSE(invalidScoreRange.IsValid());

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

    EXPECT_EQ(GetLockyVariantName(LockyVariant::Original), "Original (.locky)");
    EXPECT_EQ(GetLockyVariantName(LockyVariant::Lukitus), "Lukitus");
    EXPECT_EQ(GetDetectionConfidenceName(DetectionConfidence::Confirmed), "Confirmed");
    EXPECT_EQ(GetDetectionConfidenceName(static_cast<DetectionConfidence>(0xFF)), "None");
    EXPECT_EQ(GetLockyExtension(LockyVariant::Thor), L".thor");
    EXPECT_EQ(GetLockyExtension(LockyVariant::Ykcol), L".ykcol");
    EXPECT_EQ(LockyDetector::GetVersionString(), "3.1.0");
}

}  // namespace
