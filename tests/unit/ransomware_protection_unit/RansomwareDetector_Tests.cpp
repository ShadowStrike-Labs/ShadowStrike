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
 * @file RansomwareDetector_Tests.cpp
 * @brief Comprehensive GTest coverage for Ransomware::RansomwareDetector.
 *
 * Coverage focus:
 * - configuration validation, entropy/IO helper contracts, statistics reset, and versioning
 * - family-signature seeding, process tracking, honeypot registration, and whitelist behavior
 * - protected-path and compressed-type helpers derived from runtime configuration
 * - containment and recovery state transitions plus sub-detector alert aggregation
 */

#include "pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "RansomwareProtection_TestUtils.hpp"
#include "../../../src/PhantomCore/RansomwareProtection/RansomwareDetector.hpp"

#include <future>
#include <random>

namespace {

using namespace ShadowStrike::Ransomware;
using namespace ShadowStrike::Tests::RansomwareProtection;
using ::testing::HasSubstr;

class RansomwareDetectorTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();

        auto& detector = RansomwareDetector::Instance();
        detector.Shutdown();
        detector.ResetStatistics();

        RansomwareDetectorConfiguration config;
        config.enableAutoBlock = false;
        config.protectedDirectories = { MakePath(L"protected").wstring() + L"\\" };
        ASSERT_TRUE(detector.Initialize(config));
    }

    void TearDown() override {
        auto& detector = RansomwareDetector::Instance();
        detector.SetDetectionCallback(nullptr);
        detector.SetBlockCallback(nullptr);
        detector.SetPreWriteCallback(nullptr);
        detector.SetEmergencyBackupCallback(nullptr);
        detector.SetEmergencySnapshotCallback(nullptr);
        detector.SetLockdownCallback(nullptr);
        detector.SetRecoveryCallback(nullptr);
        detector.Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(RansomwareDetectorValueTests, ConfigurationIoStatsStatisticsUtilitiesAndVersionRemainStable) {
    RansomwareDetectorConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidEntropy = config;
    invalidEntropy.entropyThreshold = 8.1;
    EXPECT_FALSE(invalidEntropy.IsValid());

    auto invalidNegativeEntropy = config;
    invalidNegativeEntropy.entropyThreshold = -0.1;
    EXPECT_FALSE(invalidNegativeEntropy.IsValid());

    auto invalidWrites = config;
    invalidWrites.maxWritesPerSecond = 0;
    EXPECT_FALSE(invalidWrites.IsValid());

    auto invalidWindow = config;
    invalidWindow.rateWindowSecs = 0;
    EXPECT_FALSE(invalidWindow.IsValid());

    auto invalidConfidence = config;
    invalidConfidence.minBlockConfidence = 1.1;
    EXPECT_FALSE(invalidConfidence.IsValid());

    auto invalidNegativeConfidence = config;
    invalidNegativeConfidence.minBlockConfidence = -0.1;
    EXPECT_FALSE(invalidNegativeConfidence.IsValid());

    IOStats ioStats;
    ioStats.pid = 404;
    ioStats.processName = L"encryptor.exe";
    ioStats.writeCount.store(3, std::memory_order_relaxed);
    ioStats.renameCount.store(2, std::memory_order_relaxed);
    ioStats.deleteCount.store(1, std::memory_order_relaxed);
    ioStats.highEntropyWrites.store(4, std::memory_order_relaxed);
    ioStats.bytesWritten.store(1024, std::memory_order_relaxed);
    ioStats.encryptedBytesWritten.store(512, std::memory_order_relaxed);
    ioStats.writeTimestamps.assign(10, Clock::now());
    ioStats.renameTimestamps.assign(5, Clock::now());
    EXPECT_DOUBLE_EQ(
        ioStats.GetWriteRate(),
        10.0 / static_cast<double>(RansomwareConstants::RATE_WINDOW_SECS));
    EXPECT_DOUBLE_EQ(
        ioStats.GetRenameRate(),
        5.0 / static_cast<double>(RansomwareConstants::RATE_WINDOW_SECS));
    EXPECT_THAT(ioStats.ToJson(), HasSubstr("\"pid\":404"));
    EXPECT_THAT(ioStats.ToJson(), HasSubstr("\"processName\":\"encryptor.exe\""));
    ioStats.Reset();
    EXPECT_EQ(ioStats.writeCount.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(ioStats.renameCount.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(ioStats.deleteCount.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(ioStats.highEntropyWrites.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(ioStats.bytesWritten.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(ioStats.encryptedBytesWritten.load(std::memory_order_relaxed), 0u);
    EXPECT_TRUE(ioStats.writeTimestamps.empty());
    EXPECT_TRUE(ioStats.renameTimestamps.empty());
    EXPECT_EQ(ioStats.confidenceScore, 0.0);
    EXPECT_FALSE(ioStats.isBlocked);

    DetectionStatistics stats;
    stats.totalOperations.store(7, std::memory_order_relaxed);
    stats.operationsBlocked.store(6, std::memory_order_relaxed);
    stats.processesTerminated.store(5, std::memory_order_relaxed);
    stats.honeypotTriggers.store(4, std::memory_order_relaxed);
    stats.highEntropyWrites.store(3, std::memory_order_relaxed);
    stats.filesBackedUp.store(2, std::memory_order_relaxed);
    stats.filesRestored.store(1, std::memory_order_relaxed);
    stats.falsePositives.store(9, std::memory_order_relaxed);
    stats.Reset();
    EXPECT_EQ(stats.totalOperations.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.operationsBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesTerminated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.honeypotTriggers.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.highEntropyWrites.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.filesBackedUp.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.filesRestored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.falsePositives.load(std::memory_order_relaxed), 0u);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"totalOperations\":0"));

    EntropyResult entropy;
    entropy.isEncrypted = true;
    entropy.confidence = 0.9;
    EXPECT_THAT(entropy.ToJson(), HasSubstr("\"isEncrypted\":true"));

    DetectionEvent event;
    event.eventId = 1;
    event.pid = 1234;
    event.filePath = L"C:\\Victim\\doc.locked";
    event.verdict = DetectionVerdict::ConfirmedRansom;
    event.action = DetectionAction::BlockAndKill;
    event.family = RansomwareFamily::Locky;
    event.confidence = 0.95;
    event.entropyResult = entropy;
    event.details = L"high-entropy overwrite";
    EXPECT_THAT(event.ToJson(), HasSubstr("\"eventId\":1"));
    EXPECT_THAT(event.ToJson(), HasSubstr("\"entropy\":{"));
    EXPECT_THAT(event.ToJson(), HasSubstr("\"shannonEntropy\":0.0"));
    EXPECT_THAT(event.ToJson(), HasSubstr("\"details\":\"high-entropy overwrite\""));

    DetectionStatisticsSnapshot snapshot;
    snapshot.totalOperations = 8;
    snapshot.highEntropyWrites = 2;
    snapshot.uptimeSeconds = 12;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"totalOperations\":8"));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"uptimeSeconds\":12"));

    EXPECT_EQ(GetVerdictName(DetectionVerdict::Honeypot), "Honeypot");
    EXPECT_EQ(GetActionName(DetectionAction::BlockAndKill), "BlockAndKill");
    EXPECT_EQ(GetTechniqueName(DetectionTechnique::MagicCorruption), "MagicCorruption");
    EXPECT_EQ(GetFamilyName(RansomwareFamily::LockBit), "LockBit");
    EXPECT_EQ(GetRiskLevelName(ProcessRiskLevel::Critical), "Critical");
    EXPECT_EQ(GetOperationTypeName(FileOperationType::SetSecurity), "SetSecurity");
    EXPECT_EQ(GetVerdictName(static_cast<DetectionVerdict>(0xFF)), "Unknown");
    EXPECT_EQ(RansomwareDetector::GetVersionString(), "3.1.0");
}

TEST_F(RansomwareDetectorTest, InitializeSeedsFamilySignaturesAndTracksProcesses) {
    auto& detector = RansomwareDetector::Instance();

    const auto lockySignature = detector.GetFamilySignature(RansomwareFamily::Locky);
    ASSERT_TRUE(lockySignature.has_value());
    EXPECT_FALSE(lockySignature->extensions.empty());

    EXPECT_EQ(detector.IdentifyFamilyFromExtension(L".locky"), RansomwareFamily::Locky);
    EXPECT_EQ(detector.IdentifyFamilyFromExtension(L".LOCKY"), RansomwareFamily::Locky);
    EXPECT_EQ(detector.IdentifyFamilyFromExtension(L".doesnotexist"), RansomwareFamily::Unknown);

    detector.OnProcessCreated(6101, L"unit-test.exe", L"unit-test.exe");

    EXPECT_TRUE(ContainsPid(detector.GetTrackedProcesses(), 6101));
    const auto processStats = detector.GetProcessStats(6101);
    ASSERT_TRUE(processStats.has_value());
    EXPECT_EQ(processStats->processName, L"unit-test.exe");

    detector.ClearProcessStats(6101);
    EXPECT_FALSE(detector.GetProcessStats(6101).has_value());
}

TEST_F(RansomwareDetectorTest, HoneypotWhitelistContainmentAndRecoveryStateRoundTripCleanly) {
    auto& detector = RansomwareDetector::Instance();

    detector.RegisterHoneypot(L"C:\\Decoys\\Finance.docx");
    EXPECT_TRUE(detector.IsHoneypot(L"C:\\Decoys\\finance.docx"));
    EXPECT_TRUE(detector.IsHoneypot(L"c:\\decoys\\FINANCE.docx"));
    detector.UnregisterHoneypot(L"c:\\decoys\\finance.docx");
    EXPECT_FALSE(detector.IsHoneypot(L"C:\\Decoys\\finance.docx"));

    detector.WhitelistProcess(6202);
    EXPECT_TRUE(detector.IsProcessWhitelisted(6202));
    detector.OnProcessCreated(6202, L"whitelisted.exe", L"whitelisted.exe");
    EXPECT_FALSE(ContainsPid(detector.GetTrackedProcesses(), 6202));
    detector.UnwhitelistProcess(6202);
    EXPECT_FALSE(detector.IsProcessWhitelisted(6202));

    std::atomic<int> lockdownCount{ 0 };
    detector.SetLockdownCallback([&]() { ++lockdownCount; });
    detector.EnterContainmentMode();
    detector.EnterContainmentMode();
    EXPECT_TRUE(detector.IsInContainmentMode());
    EXPECT_EQ(lockdownCount.load(), 1);
    detector.ExitContainmentMode();
    EXPECT_FALSE(detector.IsInContainmentMode());

    detector.RegisterRecoveryProcess(6303);
    EXPECT_TRUE(detector.IsRecoveryProcess(6303));
    detector.UnregisterRecoveryProcess(6303);
    EXPECT_FALSE(detector.IsRecoveryProcess(6303));
}

TEST_F(RansomwareDetectorTest, ProtectedPathAndCompressedTypeHelpersHonorConfiguration) {
    auto& detector = RansomwareDetector::Instance();

    const auto protectedFile = MakePath(L"protected\\database.docx");
    const auto unprotectedFile = MakePath(L"scratch\\notes.txt");

    EXPECT_TRUE(detector.IsCompressedType(L"payload.ZIP"));
    EXPECT_FALSE(detector.IsCompressedType(L"payload.txt"));
    EXPECT_TRUE(detector.IsProtectedPath(protectedFile.wstring()));
    EXPECT_FALSE(detector.IsProtectedPath(unprotectedFile.wstring()));

    detector.Shutdown();
    detector.ResetStatistics();

    RansomwareDetectorConfiguration boundaryConfig;
    boundaryConfig.enableAutoBlock = false;
    boundaryConfig.protectedDirectories = { MakePath(L"protected").wstring() };
    ASSERT_TRUE(detector.Initialize(boundaryConfig));

    EXPECT_TRUE(detector.IsProtectedPath(protectedFile.wstring()));
    EXPECT_FALSE(detector.IsProtectedPath(MakePath(L"protected-old\\database.docx").wstring()));
}

TEST_F(RansomwareDetectorTest, SubDetectorIndicatorsProduceHighRiskProcessesAndRecentDetections) {
    auto& detector = RansomwareDetector::Instance();

    std::promise<DetectionEvent> detectionPromise;
    auto detectionFuture = detectionPromise.get_future();
    std::atomic<bool> detectionDelivered{ false };
    detector.SetDetectionCallback(
        [&](const DetectionEvent& event) {
            if (!detectionDelivered.exchange(true)) {
                detectionPromise.set_value(event);
            }
        });

    detector.OnSubDetectorIndicator(6404, 60.0, RansomwareFamily::Locky, L"Locky-like behavior");

    ASSERT_EQ(detectionFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const auto detection = detectionFuture.get();
    EXPECT_EQ(detection.pid, 6404u);
    EXPECT_EQ(detection.family, RansomwareFamily::Locky);
    EXPECT_EQ(detection.verdict, DetectionVerdict::Suspicious);
    EXPECT_EQ(detection.action, DetectionAction::AllowWithBackup);

    EXPECT_TRUE(ContainsPid(detector.GetHighRiskProcesses(), 6404));

    const auto recent = detector.GetRecentDetections(5);
    ASSERT_FALSE(recent.empty());
    EXPECT_EQ(recent.front().pid, 6404u);
    EXPECT_EQ(recent.front().family, RansomwareFamily::Locky);
    EXPECT_TRUE(detector.GetRecentDetections(0).empty());
}

TEST_F(RansomwareDetectorTest, EntropyHelpersDifferentiateLowAndHighEntropyBuffers) {
    auto& detector = RansomwareDetector::Instance();

    const std::vector<uint8_t> lowEntropy(1024, 0);

    std::mt19937 generator(42);
    std::uniform_int_distribution<int> distribution(0, 255);
    std::vector<uint8_t> highEntropy(4096);
    for (auto& value : highEntropy) {
        value = static_cast<uint8_t>(distribution(generator));
    }

    const std::vector<uint8_t> empty;
    const std::vector<uint8_t> tiny(8, 0x41);

    EXPECT_DOUBLE_EQ(RansomwareDetector::CalculateEntropy(empty), 0.0);
    EXPECT_DOUBLE_EQ(RansomwareDetector::CalculateEntropy(lowEntropy), 0.0);

    const auto tinyAnalyzed = RansomwareDetector::AnalyzeEntropy(tiny);
    const auto analyzed = RansomwareDetector::AnalyzeEntropy(highEntropy);
    EXPECT_DOUBLE_EQ(tinyAnalyzed.shannonEntropy, 0.0);
    EXPECT_FALSE(tinyAnalyzed.isEncrypted);
    EXPECT_GT(analyzed.shannonEntropy, 7.0);
    EXPECT_TRUE(RansomwareDetector::IsEncrypted(highEntropy));
    EXPECT_FALSE(RansomwareDetector::IsEncrypted(tiny));
    EXPECT_FALSE(RansomwareDetector::IsEncrypted(lowEntropy));
    EXPECT_TRUE(detector.SelfTest());
}

}  // namespace
