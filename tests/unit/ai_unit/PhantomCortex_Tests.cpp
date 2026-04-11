/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PhantomCortex orchestration behavior.
 *
 * Scope:
 *   - non-operational guard behavior for every public analysis surface
 *   - deterministic ensemble aggregation
 *   - runtime statistics and model-update guard paths
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

#include "../../../src/PhantomCore/AI/PhantomCortex.hpp"
#include "AI_TestUtils.hpp"

namespace fs = std::filesystem;

namespace ShadowStrike::AI::Test {

namespace {

void ExpectErrorVerdict(const CortexVerdict& verdict,
                        const CortexModelType expectedSource,
                        std::wstring_view expectedDetailFragment) {
    EXPECT_EQ(verdict.verdict, ThreatVerdict::Benign);
    EXPECT_FLOAT_EQ(verdict.confidence, 0.0f);
    EXPECT_EQ(verdict.source, expectedSource);
    EXPECT_NE(verdict.details.find(expectedDetailFragment), std::wstring::npos);
}

}  // namespace

class PhantomCortexTest : public ::testing::Test {
protected:
    void SetUp() override {
        PhantomCortex::Instance().Shutdown();
    }

    void TearDown() override {
        PhantomCortex::Instance().Shutdown();
    }
};

TEST_F(PhantomCortexTest, InstanceReturnsStableSingletonReference) {
    auto& first = PhantomCortex::Instance();
    auto& second = PhantomCortex::Instance();

    EXPECT_EQ(&first, &second);
}

TEST_F(PhantomCortexTest, ShutdownLeavesEngineNonOperational) {
    PhantomCortex::Instance().Shutdown();
    EXPECT_FALSE(PhantomCortex::Instance().IsOperational());
}

TEST_F(PhantomCortexTest, AnalyzeFileReturnsErrorVerdictWhenEngineIsNotOperational) {
    const std::vector<uint8_t> fileBytes = {0x4D, 0x5A, 0x90, 0x00};
    const CortexVerdict verdict = PhantomCortex::Instance().AnalyzeFile(fileBytes);

    ExpectErrorVerdict(verdict, CortexModelType::Static, L"not operational");
}

TEST_F(PhantomCortexTest, AnalyzeBehaviorReturnsErrorVerdictWhenEngineIsNotOperational) {
    const std::array<APICallRecord, 1> calls = {{{0x1000, 0x2000, 0, 1.0f}}};
    const CortexVerdict verdict = PhantomCortex::Instance().AnalyzeBehavior(calls);

    ExpectErrorVerdict(verdict, CortexModelType::Behavioral, L"not operational");
}

TEST_F(PhantomCortexTest, AnalyzeMemoryReturnsErrorVerdictWhenEngineIsNotOperational) {
    const std::array<uint8_t, 4> bytes = {0x90, 0x90, 0xC3, 0x00};
    MemoryRegionInfo region{};
    region.data = bytes;
    region.baseAddress = 0x401000;
    region.size = bytes.size();
    region.protection = 0x40;

    const CortexVerdict verdict = PhantomCortex::Instance().AnalyzeMemory(region);
    ExpectErrorVerdict(verdict, CortexModelType::Memory, L"not operational");
}

TEST_F(PhantomCortexTest, AnalyzeNetworkReturnsErrorVerdictWhenEngineIsNotOperational) {
    NetworkFlowInfo flow{};
    flow.srcIPv4 = 0x0A000001;
    flow.dstIPv4 = 0x0A000002;
    flow.srcPort = 1234;
    flow.dstPort = 443;

    const CortexVerdict verdict = PhantomCortex::Instance().AnalyzeNetwork(flow);
    ExpectErrorVerdict(verdict, CortexModelType::Network, L"not operational");
}

TEST_F(PhantomCortexTest, AnalyzeEmulationTraceReturnsErrorVerdictWhenEngineIsNotOperational) {
    const std::array<EmulationEvent, 1> events = {{{1, 2, 3, 0x1}}};
    const CortexVerdict verdict = PhantomCortex::Instance().AnalyzeEmulationTrace(events);

    ExpectErrorVerdict(verdict, CortexModelType::Emulation, L"not operational");
}

TEST_F(PhantomCortexTest, EnsembleVerdictWithNoParticipantsReturnsBenignZeroConfidence) {
    const auto ensemble = PhantomCortex::Instance().EnsembleVerdict(
        std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);

    EXPECT_EQ(ensemble.finalVerdict, ThreatVerdict::Benign);
    EXPECT_FLOAT_EQ(ensemble.ensembleConfidence, 0.0f);
    EXPECT_EQ(ensemble.totalInferenceTime, std::chrono::microseconds{0});
    EXPECT_EQ(ensemble.modelVerdicts[0].source, CortexModelType::Static);
    EXPECT_EQ(ensemble.modelVerdicts[4].source, CortexModelType::Emulation);
}

TEST_F(PhantomCortexTest, EnsembleVerdictAggregatesWeightsConfidenceAndLatency) {
    CortexVerdict staticVerdict{};
    staticVerdict.source = CortexModelType::Static;
    staticVerdict.verdict = ThreatVerdict::Malicious;
    staticVerdict.confidence = 1.0f;
    staticVerdict.inferenceTime = std::chrono::microseconds{120};

    CortexVerdict behavioralVerdict{};
    behavioralVerdict.source = CortexModelType::Behavioral;
    behavioralVerdict.verdict = ThreatVerdict::Suspicious;
    behavioralVerdict.confidence = 1.0f;
    behavioralVerdict.inferenceTime = std::chrono::microseconds{80};

    const auto ensemble = PhantomCortex::Instance().EnsembleVerdict(
        staticVerdict, behavioralVerdict, std::nullopt, std::nullopt, std::nullopt);

    EXPECT_NEAR(ensemble.ensembleConfidence, 0.425f / 0.55f, 1e-6f);
    EXPECT_EQ(ensemble.finalVerdict, ThreatVerdict::Malicious);
    EXPECT_EQ(ensemble.totalInferenceTime, std::chrono::microseconds{200});
    EXPECT_EQ(ensemble.modelVerdicts[0].verdict, ThreatVerdict::Malicious);
    EXPECT_EQ(ensemble.modelVerdicts[1].verdict, ThreatVerdict::Suspicious);
}

TEST_F(PhantomCortexTest, EnsembleVerdictBelowThresholdRemainsBenign) {
    CortexVerdict behavioralVerdict{};
    behavioralVerdict.source = CortexModelType::Behavioral;
    behavioralVerdict.verdict = ThreatVerdict::Suspicious;
    behavioralVerdict.confidence = 0.6f;
    behavioralVerdict.inferenceTime = std::chrono::microseconds{50};

    const auto ensemble = PhantomCortex::Instance().EnsembleVerdict(
        std::nullopt, behavioralVerdict, std::nullopt, std::nullopt, std::nullopt);

    EXPECT_NEAR(ensemble.ensembleConfidence, 0.3f, 1e-6f);
    EXPECT_EQ(ensemble.finalVerdict, ThreatVerdict::Benign);
}

TEST_F(PhantomCortexTest, EnsembleVerdictHonorsStrictThresholdBoundaries) {
    CortexVerdict thresholdVerdict{};
    thresholdVerdict.source = CortexModelType::Static;
    thresholdVerdict.verdict = ThreatVerdict::Malicious;
    thresholdVerdict.confidence = 0.5f;

    const auto atThreshold = PhantomCortex::Instance().EnsembleVerdict(
        thresholdVerdict, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_FLOAT_EQ(atThreshold.ensembleConfidence, 0.5f);
    EXPECT_EQ(atThreshold.finalVerdict, ThreatVerdict::Benign);

    CortexVerdict edgeVerdict = thresholdVerdict;
    edgeVerdict.confidence = 0.7f;
    const auto atMaliciousBoundary = PhantomCortex::Instance().EnsembleVerdict(
        edgeVerdict, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_FLOAT_EQ(atMaliciousBoundary.ensembleConfidence, 0.7f);
    EXPECT_EQ(atMaliciousBoundary.finalVerdict, ThreatVerdict::Suspicious);
}

TEST_F(PhantomCortexTest, EnsembleVerdictClampsReportedConfidenceForMalformedInputs) {
    CortexVerdict excessiveConfidence{};
    excessiveConfidence.source = CortexModelType::Static;
    excessiveConfidence.verdict = ThreatVerdict::Malicious;
    excessiveConfidence.confidence = 3.5f;

    const auto clampedHigh = PhantomCortex::Instance().EnsembleVerdict(
        excessiveConfidence, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_FLOAT_EQ(clampedHigh.ensembleConfidence, 1.0f);
    EXPECT_EQ(clampedHigh.finalVerdict, ThreatVerdict::Malicious);

    CortexVerdict negativeConfidence = excessiveConfidence;
    negativeConfidence.confidence = -2.0f;
    const auto clampedLow = PhantomCortex::Instance().EnsembleVerdict(
        negativeConfidence, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_FLOAT_EQ(clampedLow.ensembleConfidence, 0.0f);
    EXPECT_EQ(clampedLow.finalVerdict, ThreatVerdict::Benign);
}

TEST_F(PhantomCortexTest, GetStatsIsZeroWhenEngineIsIdle) {
    const auto stats = PhantomCortex::Instance().GetStats();

    EXPECT_EQ(stats.totalInferences, 0u);
    EXPECT_EQ(stats.totalMaliciousDetections, 0u);
    EXPECT_EQ(stats.totalSuspiciousDetections, 0u);
    EXPECT_EQ(stats.totalBenignClassifications, 0u);
    EXPECT_EQ(stats.averageInferenceTimeUs, 0u);
    EXPECT_EQ(stats.modelLoadErrors, 0u);
}

TEST_F(PhantomCortexTest, GuardFailuresDoNotMutateRuntimeStatistics) {
    const std::vector<uint8_t> fileBytes = {0x4D, 0x5A, 0x90, 0x00};
    MemoryRegionInfo region{};
    const std::array<uint8_t, 4> regionBytes = {0x90, 0x90, 0xC3, 0x00};
    region.data = regionBytes;
    region.size = regionBytes.size();

    NetworkFlowInfo flow{};
    const std::array<APICallRecord, 1> calls = {{{1, 2, 3, 4.0f}}};
    const std::array<EmulationEvent, 1> events = {{{1, 2, 3, 0x1}}};

    (void)PhantomCortex::Instance().AnalyzeFile(fileBytes);
    (void)PhantomCortex::Instance().AnalyzeBehavior(calls);
    (void)PhantomCortex::Instance().AnalyzeMemory(region);
    (void)PhantomCortex::Instance().AnalyzeNetwork(flow);
    (void)PhantomCortex::Instance().AnalyzeEmulationTrace(events);

    const auto stats = PhantomCortex::Instance().GetStats();
    EXPECT_EQ(stats.totalInferences, 0u);
    EXPECT_EQ(stats.totalMaliciousDetections, 0u);
    EXPECT_EQ(stats.totalSuspiciousDetections, 0u);
    EXPECT_EQ(stats.totalBenignClassifications, 0u);
    EXPECT_EQ(stats.averageInferenceTimeUs, 0u);
    EXPECT_EQ(stats.modelLoadErrors, 0u);
}

TEST_F(PhantomCortexTest, UpdateModelsRejectsMissingDirectory) {
    EXPECT_FALSE(PhantomCortex::Instance().UpdateModels(
        fs::path{L"C:\\DefinitelyMissing\\ShadowStrike\\PhantomCortex\\Models"}));
}

TEST_F(PhantomCortexTest, UpdateModelsRejectsRegularFilePath) {
    ScopedTempDir tempDir{L"ShadowStrike_AIPhantomCortex_"};
    const fs::path filePath = tempDir.File(L"not_a_directory.bin");
    std::ofstream stream(filePath, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(stream.good());
    stream << "not a directory";
    stream.close();

    EXPECT_FALSE(PhantomCortex::Instance().UpdateModels(filePath));
}

TEST_F(PhantomCortexTest, GetModelVersionsReturnsEmptySlotsWhenNothingIsLoaded) {
    const auto versions = PhantomCortex::Instance().GetModelVersions();

    EXPECT_TRUE(std::all_of(
        versions.begin(),
        versions.end(),
        [](const auto& version) { return !version.has_value(); }));
}

}  // namespace ShadowStrike::AI::Test
