/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PolymorphicDetector deterministic behavior.
 *
 * Scope:
 *   - configuration validation and JSON surfaces consumed by diagnostics
 *   - statistics reset and telemetry helper naming
 *   - pre-init guards plus lightweight initialized helper behavior
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <atomic>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/Core/Engine/PolymorphicDetector.hpp"

namespace Engine = ShadowStrike::Core::Engine;

namespace ShadowStrike::Core::Engine::Test {
namespace {

bool Contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

}  // namespace

class PolymorphicDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        Engine::PolymorphicDetector::Instance().Shutdown();
    }

    void TearDown() override {
        Engine::PolymorphicDetector::Instance().Shutdown();
    }
};

TEST_F(PolymorphicDetectorTest, JsonAndValidationHelpersRemainStable) {
    Engine::DecryptionLoopInfo loop;
    loop.loopStart = 0x1000;
    loop.loopEnd = 0x1010;
    loop.iterations = 4;
    loop.algorithm = "XOR";
    loop.decryptedStart = 0x2000;
    loop.decryptedSize = 32;
    loop.xorKey = std::vector<uint8_t>{0x41, 0x42};
    EXPECT_TRUE(Contains(loop.ToJson(), "\"keyLength\":2"));

    Engine::JunkCodeRegion junk;
    junk.startOffset = 4;
    junk.endOffset = 8;
    junk.size = 4;
    junk.patternType = "nop-sled";
    EXPECT_TRUE(Contains(junk.ToJson(), "\"type\":\"nop-sled\""));

    Engine::NormalizationResult normalization;
    normalization.originalSize = 64;
    normalization.normalizedSize = 32;
    normalization.reductionRatio = 0.5f;
    normalization.instructionsRemoved = 10;
    normalization.passesPerformed = 3;
    normalization.processingTimeMs = 11;
    normalization.junkRegions = {junk};
    EXPECT_TRUE(Contains(normalization.ToJson(), "\"junkRegions\":1"));

    Engine::FuzzyHashMatch match;
    match.score = 88;
    match.matchedHash = std::string(40, 'A');
    match.threatName = "PackedSample";
    match.familyName = "Shadow";
    match.variant = "A";
    const std::string matchJson = match.ToJson();
    EXPECT_TRUE(Contains(matchJson, "\"score\":88"));
    EXPECT_TRUE(Contains(matchJson, "\"matchedHash\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...\""));

    Engine::PolyResult result;
    result.isPolymorphic = true;
    result.engineName = "MtE";
    result.confidence = Engine::PolymorphicDetectionConfidence::High;
    result.mutations = {Engine::MutationType::Encryption, Engine::MutationType::JunkInsertion};
    result.decryptionLoops = {loop};
    result.fuzzyMatches = {match};
    result.analysisTimeMs = 25;
    result.fuzzyHash = std::string(64, 'B');
    result.tlshHash = std::string(64, 'C');
    result.threatFamily = "ShadowFamily";
    const std::string resultJson = result.ToJson();
    EXPECT_TRUE(Contains(resultJson, "\"mutations\":2"));
    EXPECT_TRUE(Contains(resultJson, "\"threatFamily\":\"ShadowFamily\""));
    EXPECT_TRUE(Contains(resultJson, "\"fuzzyHash\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB...\""));
    EXPECT_TRUE(Contains(resultJson, "\"tlshHash\":\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC...\""));

    Engine::PolyAnalysisOptions options;
    EXPECT_TRUE(options.IsValid());
    options.fuzzyThreshold = 101;
    EXPECT_FALSE(options.IsValid());
    options = {};
    options.maxAnalysisTimeMs = 0;
    EXPECT_FALSE(options.IsValid());

    Engine::PolymorphicConfiguration config;
    EXPECT_TRUE(config.IsValid());
    config.workerThreads = 0;
    EXPECT_FALSE(config.IsValid());
    config = {};
    config.enableCaching = true;
    config.cacheTtlSeconds = 0;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(PolymorphicDetectorTest, StatisticsResetAndNameHelpersRemainDeterministic) {
    Engine::PolyStatistics stats;
    stats.totalAnalyses.store(9, std::memory_order_relaxed);
    stats.polymorphicDetected.store(4, std::memory_order_relaxed);
    stats.fuzzyMatches.store(3, std::memory_order_relaxed);
    stats.byEngineType[static_cast<size_t>(Engine::PolyEngineType::MtE)]
        .store(2, std::memory_order_relaxed);

    const std::string json = stats.ToJson();
    EXPECT_TRUE(Contains(json, "\"totalAnalyses\":9"));
    EXPECT_TRUE(Contains(json, "\"fuzzyMatches\":3"));

    stats.Reset();
    EXPECT_EQ(stats.totalAnalyses.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.polymorphicDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.fuzzyMatches.load(std::memory_order_relaxed), 0u);

    EXPECT_EQ(Engine::GetPolyEngineTypeName(Engine::PolyEngineType::MtE), "MtE");
    EXPECT_EQ(Engine::GetMutationTypeName(Engine::MutationType::JunkInsertion), "JunkInsertion");
    EXPECT_EQ(Engine::GetNormalizationLevelName(Engine::NormalizationLevel::Full), "Full");
    EXPECT_EQ(
        Engine::GetPolymorphicDetectionConfidenceName(Engine::PolymorphicDetectionConfidence::High),
        "High");
}

TEST_F(PolymorphicDetectorTest, PreInitializationGuardsReturnSafeDefaults) {
    auto& detector = Engine::PolymorphicDetector::Instance();
    EXPECT_FALSE(detector.IsInitialized());
    EXPECT_EQ(detector.GetStatus(), Engine::PolyDetectorStatus::Uninitialized);

    const std::vector<uint8_t> code = {0x90, 0x90, 0xEB, 0x00, 0xCC};
    const Engine::PolyResult result = detector.Analyze(code);
    EXPECT_FALSE(result.isPolymorphic);
    EXPECT_TRUE(result.engineName.empty());

    std::atomic<bool> callbackInvoked = false;
    detector.AnalyzeAsync(code, [&callbackInvoked](const Engine::PolyResult& asyncResult) {
        callbackInvoked.store(true, std::memory_order_relaxed);
        EXPECT_FALSE(asyncResult.isPolymorphic);
    });
    EXPECT_TRUE(callbackInvoked.load(std::memory_order_relaxed));
    detector.AnalyzeAsync(code, nullptr);

    EXPECT_EQ(detector.NormalizeInstructions(code), code);
    EXPECT_TRUE(detector.NormalizeCode(code).normalizedCode.empty());
    EXPECT_EQ(detector.RemoveJunkCode(code), code);
    EXPECT_EQ(detector.NormalizeRegisters(code), code);
    EXPECT_FALSE(detector.DetectEngine(code).has_value());
    EXPECT_TRUE(detector.DetectMutations(code).empty());
    EXPECT_TRUE(detector.FindDecryptionLoops(code).empty());
    EXPECT_FALSE(detector.ExtractXORKey(code).has_value());
    EXPECT_FALSE(detector.DecryptPayload(code, {0xAA}).has_value());
    EXPECT_TRUE(detector.FuzzyMatch(code).empty());
    EXPECT_TRUE(detector.CalculateFuzzyHash(code).empty());
    EXPECT_TRUE(detector.CalculateTLSH(code).empty());
    EXPECT_EQ(detector.CompareFuzzyHash("a", "b"), 0u);
    EXPECT_FALSE(detector.SelfTest());
}

TEST_F(PolymorphicDetectorTest, InitializedHelpersSupportDeterministicDecryptionPaths) {
    auto& detector = Engine::PolymorphicDetector::Instance();
    ASSERT_TRUE(detector.Initialize());
    EXPECT_TRUE(detector.IsInitialized());
    EXPECT_TRUE(detector.SelfTest());

    const std::vector<uint8_t> encrypted = {0x10, 0x11, 0x12, 0x13};
    const auto decrypted = detector.DecryptPayload(encrypted, {0x01, 0x02});
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, (std::vector<uint8_t>{0x11, 0x13, 0x13, 0x11}));
    EXPECT_FALSE(detector.DecryptPayload({}, {0x01}).has_value());
    EXPECT_FALSE(detector.DecryptPayload(encrypted, {}).has_value());

    const std::vector<uint8_t> junkHeavyCode = {0x90, 0x90, 0xEB, 0x00, 0xCC, 0x58, 0xC3};
    const std::vector<uint8_t> cleaned = detector.RemoveJunkCode(junkHeavyCode);
    EXPECT_EQ(cleaned, (std::vector<uint8_t>{0xCC, 0x58, 0xC3}));

    EXPECT_EQ(detector.GetEngineName(Engine::PolyEngineType::MtE), "MtE");
    EXPECT_FALSE(Engine::IsPotentiallyPolymorphic(std::span<const uint8_t>{}));
    EXPECT_FLOAT_EQ(Engine::GetCodeEntropy(std::span<const uint8_t>{}), 0.0f);

    std::vector<uint8_t> highEntropyCode(256);
    for (size_t i = 0; i < highEntropyCode.size(); ++i) {
        highEntropyCode[i] = static_cast<uint8_t>(i);
    }
    EXPECT_TRUE(Engine::IsPotentiallyPolymorphic(highEntropyCode));
}

}  // namespace ShadowStrike::Core::Engine::Test
