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
 * @file WannaCryDetector_ValueContracts_Tests.cpp
 * @brief Value-contract coverage for Ransomware::WannaCryDetector.
 */

#include "pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../../src/PhantomCore/RansomwareProtection/WannaCryDetector.hpp"

namespace {

using namespace ShadowStrike::Ransomware;
using ::testing::HasSubstr;

TEST(WannaCryDetectorValueContractTests, ConfigStatisticsHelpersAndVersionRemainStable) {
    WannaCryDetectorConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidThreshold = config;
    invalidThreshold.smbScanThreshold = 0;
    EXPECT_FALSE(invalidThreshold.IsValid());

    auto invalidWindow = config;
    invalidWindow.smbScanWindowSecs = 0;
    EXPECT_FALSE(invalidWindow.IsValid());

    auto invalidCache = config;
    invalidCache.cacheTTLSecs = 0;
    EXPECT_FALSE(invalidCache.IsValid());

    WannaCryStatistics stats;
    stats.totalDetections.store(3, std::memory_order_relaxed);
    stats.byVariant[static_cast<size_t>(WannaCryVariant::BadRabbit)].store(9, std::memory_order_relaxed);
    stats.smbExploitsBlocked.store(1, std::memory_order_relaxed);
    stats.killSwitchQueries.store(2, std::memory_order_relaxed);
    stats.processesTerminated.store(4, std::memory_order_relaxed);
    stats.hostsProtected.store(5, std::memory_order_relaxed);
    stats.smbScansDetected.store(6, std::memory_order_relaxed);
    stats.mutexDetections.store(7, std::memory_order_relaxed);
    stats.serviceDetections.store(8, std::memory_order_relaxed);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"hostsProtected\":5"));
    stats.Reset();

    EXPECT_EQ(stats.totalDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.smbExploitsBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.killSwitchQueries.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesTerminated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.hostsProtected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.smbScansDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.mutexDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.serviceDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(
        stats.byVariant[static_cast<size_t>(WannaCryVariant::BadRabbit)].load(
            std::memory_order_relaxed),
        0u);

    WannaCryDetectionResult result;
    result.variant = WannaCryVariant::BadRabbit;
    result.phase = WannaCryPhase::Propagation;
    result.confidence = DetectionConfidence::High;
    result.processName = L"tasksche.exe";
    result.killSwitchDomain = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com";
    EXPECT_THAT(result.ToJson(), HasSubstr("BadRabbit"));
    EXPECT_THAT(result.ToJson(), HasSubstr("Propagation"));
    EXPECT_THAT(result.ToJson(), HasSubstr("High"));
    EXPECT_THAT(result.ToJson(), HasSubstr("\"processName\":\"tasksche.exe\""));
    EXPECT_THAT(result.ToJson(), HasSubstr("\"killSwitchDomain\":\"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\""));

    WannaCryStatisticsSnapshot snapshot;
    snapshot.totalDetections = 4;
    snapshot.hostsProtected = 2;
    snapshot.uptimeSeconds = 10;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"hostsProtected\":2"));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"uptimeSeconds\":10"));

    EXPECT_EQ(GetWannaCryVariantName(WannaCryVariant::WannaCryNoKill),
              "WannaCry (No Kill-Switch)");
    EXPECT_EQ(GetWannaCryPhaseName(WannaCryPhase::MBROverwrite), "MBR Overwrite");
    EXPECT_EQ(GetDetectionConfidenceName(DetectionConfidence::Confirmed), "Confirmed");
    EXPECT_EQ(GetDetectionConfidenceName(static_cast<DetectionConfidence>(0xFF)), "Unknown");
    EXPECT_EQ(GetWannaCryVariantName(static_cast<WannaCryVariant>(0xFF)), "Unknown");
    EXPECT_EQ(GetWannaCryPhaseName(static_cast<WannaCryPhase>(0xFF)), "Unknown");
    EXPECT_EQ(WannaCryDetector::GetVersionString(), "3.2.0");
}

TEST(WannaCryDetectorValueContractTests, AnEternalBlueIndicatorClaimsNothingByDefault) {
    // The DEFAULT is the contract here, and a default cannot be found by grepping for an
    // assignment - which is precisely how a wrong one survives review. AnalyzeSMBTraffic
    // receives a std::span<const uint8_t> and holds no transport, so it can never prevent
    // an exploit; an indicator that arrives claiming otherwise is a false report.
    EternalBlueIndicator indicator;
    EXPECT_FALSE(indicator.wasBlocked)
        << "a default-constructed EternalBlue indicator must not claim the exploit was blocked";
    EXPECT_FALSE(indicator.blockRequested)
        << "a default-constructed EternalBlue indicator must not claim policy asked for a block";
    EXPECT_FALSE(indicator.signatureMatched);
    EXPECT_EQ(indicator.exploitStage, 0u);
}

TEST(WannaCryDetectorValueContractTests, TheSmbDetectionCounterSurvivesCopyAndReset) {
    // WannaCryStatistics hand-writes BOTH copy operators so its atomics load safely, and
    // GetStatistics() copies. A member added to the declaration alone is therefore dropped
    // on every copy and reads as a structural zero forever, while the declaration looks
    // correct to a reader. That is task 102's defect reached by another route.
    WannaCryStatistics stats;
    stats.smbExploitsDetected.store(11, std::memory_order_relaxed);
    stats.smbExploitsBlocked.store(0, std::memory_order_relaxed);

    WannaCryStatistics copied(stats);
    EXPECT_EQ(copied.smbExploitsDetected.load(std::memory_order_relaxed), 11u)
        << "the hand-written copy constructor dropped the SMB detection counter";

    WannaCryStatistics assigned;
    assigned = stats;
    EXPECT_EQ(assigned.smbExploitsDetected.load(std::memory_order_relaxed), 11u)
        << "the hand-written assignment operator dropped the SMB detection counter";

    // Detections and preventions must be separately readable, or the gap between "we saw
    // EternalBlue" and "we stopped it" cannot be recovered from the numbers at all.
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"smbExploitsDetected\":11"));
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"smbExploitsBlocked\":0"));

    stats.Reset();
    EXPECT_EQ(stats.smbExploitsDetected.load(std::memory_order_relaxed), 0u)
        << "Reset() left the SMB detection counter holding a pre-reset value";

    WannaCryStatisticsSnapshot snapshot;
    snapshot.smbExploitsDetected = 7;
    snapshot.smbExploitsBlocked = 0;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"smbExploitsDetected\":7"));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"smbExploitsBlocked\":0"));
}

}  // namespace
