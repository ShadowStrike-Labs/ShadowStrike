/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <climits>
#include <gtest/gtest.h>

#include "../../../src/Shared_modules/AntiEvasion/metamorphic_polymorphicdetector.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(MetamorphicDetector_Helpers, TechniqueMetadataAndStringMappingsRemainStable) {
    EXPECT_STREQ("T1027", MetamorphicTechniqueToMitreId(MetamorphicTechnique::META_InstructionSubstitution));
    EXPECT_STREQ("T1027.002", MetamorphicTechniqueToMitreId(MetamorphicTechnique::PACK_UPX));

    EXPECT_EQ(MetamorphicCategory::Metamorphic,
        GetTechniqueCategory(MetamorphicTechnique::META_InstructionSubstitution));
    EXPECT_EQ(MetamorphicCategory::Obfuscation,
        GetTechniqueCategory(MetamorphicTechnique::OBF_ControlFlowFlattening));
    EXPECT_EQ(MetamorphicCategory::Combined,
        GetTechniqueCategory(MetamorphicTechnique::ADV_SophisticatedEvasion));

    EXPECT_STREQ(L"Instruction Substitution",
        MetamorphicTechniqueToString(MetamorphicTechnique::META_InstructionSubstitution));
    EXPECT_STREQ(L"Control Flow Flattening",
        MetamorphicTechniqueToString(MetamorphicTechnique::OBF_ControlFlowFlattening));
    EXPECT_STREQ(L"Sophisticated Evasion",
        MetamorphicTechniqueToString(MetamorphicTechnique::ADV_SophisticatedEvasion));
    EXPECT_STREQ(L"Unknown Technique",
        MetamorphicTechniqueToString(static_cast<MetamorphicTechnique>(0xFFFF)));
}

TEST(MetamorphicDetector_Entropy, CalculateEntropyHandlesLowAndHighEntropyBuffers) {
    MetamorphicDetector detector;

    std::vector<uint8_t> zeros(1024, 0x00);
    std::vector<uint8_t> alternating(1024);
    for (size_t i = 0; i < alternating.size(); ++i) {
        alternating[i] = static_cast<uint8_t>(i % 2 == 0 ? 0x00 : 0xFF);
    }

    std::vector<uint8_t> fullRange(256);
    for (size_t i = 0; i < fullRange.size(); ++i) {
        fullRange[i] = static_cast<uint8_t>(i);
    }

    EXPECT_DOUBLE_EQ(0.0, detector.CalculateEntropy(nullptr, 0));
    EXPECT_NEAR(0.0, detector.CalculateEntropy(zeros.data(), zeros.size()), 1e-9);
    EXPECT_NEAR(1.0, detector.CalculateEntropy(alternating.data(), alternating.size()), 0.05);
    EXPECT_NEAR(8.0, detector.CalculateEntropy(fullRange.data(), fullRange.size()), 0.05);
}

TEST(MetamorphicDetector_Similarity, CompareFunctionsRejectMalformedHashesSafely) {
    MetamorphicDetector detector;

    EXPECT_EQ(0, detector.CompareFuzzyHash("", "3:abcdef:abcdef"));
    EXPECT_EQ(0, detector.CompareFuzzyHash("invalid-format", "3:abcdef:abcdef"));
    EXPECT_EQ(INT_MAX, detector.CompareTLSH("", "T1ABCDEF"));
    EXPECT_EQ(INT_MAX, detector.CompareTLSH("T1ABCDEF", "T1ABCDEF"));
}

TEST(MetamorphicDetector_Builder, DetectionBuilderPopulatesDerivedMetadataAndPayload) {
    const std::array<uint8_t, 4> rawData{ 0x90, 0x90, 0xEB, 0xFE };

    const auto detection = MetamorphicDetectionBuilder{}
        .Technique(MetamorphicTechnique::OBF_ControlFlowFlattening)
        .Confidence(0.88)
        .Location(0x401000)
        .ArtifactSize(rawData.size())
        .Description(L"Dispatcher flattening observed")
        .TechnicalDetails(L"Flattened control transfer graph")
        .RawData(rawData.data(), rawData.size())
        .Build();

    EXPECT_EQ(MetamorphicTechnique::OBF_ControlFlowFlattening, detection.technique);
    EXPECT_EQ(GetTechniqueCategory(MetamorphicTechnique::OBF_ControlFlowFlattening), detection.category);
    EXPECT_EQ(GetDefaultTechniqueSeverity(MetamorphicTechnique::OBF_ControlFlowFlattening), detection.severity);
    EXPECT_STREQ(MetamorphicTechniqueToMitreId(MetamorphicTechnique::OBF_ControlFlowFlattening),
        detection.mitreId.c_str());
    EXPECT_DOUBLE_EQ(0.88, detection.confidence);
    EXPECT_EQ(0x401000u, detection.location);
    EXPECT_EQ(rawData.size(), detection.artifactSize);
    EXPECT_EQ(L"Dispatcher flattening observed", detection.description);
    EXPECT_EQ(L"Flattened control transfer graph", detection.technicalDetails);
    EXPECT_EQ(std::vector<uint8_t>(rawData.begin(), rawData.end()), detection.rawData);
    EXPECT_GT(detection.detectionTime, std::chrono::system_clock::time_point{});
}

TEST(MetamorphicDetector_ResultHelpers, CategoryFilteringAndClearResetSimilarityState) {
    MetamorphicResult result;
    result.filePath = L"C:\\Temp\\sample.bin";
    result.processId = 1001;
    result.sha256Hash = "deadbeef";
    result.fileSize = 4096;
    result.isMetamorphic = true;
    result.mutationScore = 84.5;
    result.maxSeverity = MetamorphicSeverity::Critical;
    result.totalDetections = 2;
    result.detectedCategories =
        (1u << static_cast<uint32_t>(MetamorphicCategory::Metamorphic)) |
        (1u << static_cast<uint32_t>(MetamorphicCategory::Obfuscation));
    result.detectedTechniques = {
        MetamorphicDetectionBuilder{}
            .Technique(MetamorphicTechnique::META_InstructionSubstitution)
            .Confidence(0.92)
            .Build(),
        MetamorphicDetectionBuilder{}
            .Technique(MetamorphicTechnique::OBF_ControlFlowFlattening)
            .Confidence(0.73)
            .Build()
    };
    result.fuzzyHash = "3:abcdef:abcdef";
    result.tlshHash = "T1ABCDEF123456789";
    result.ngramProfile = { 1, 2, 3, 5, 8 };
    result.similarityAnalysisComplete = true;
    result.analysisComplete = true;
    result.fromCache = true;

    EXPECT_TRUE(result.HasCategory(MetamorphicCategory::Metamorphic));
    EXPECT_TRUE(result.HasTechnique(MetamorphicTechnique::OBF_ControlFlowFlattening));
    EXPECT_FALSE(result.HasCategory(MetamorphicCategory::CodeGeneration));
    EXPECT_FALSE(result.HasTechnique(MetamorphicTechnique::PACK_UPX));
    EXPECT_EQ(1u, result.GetCategoryCount(MetamorphicCategory::Obfuscation));
    EXPECT_EQ(0u, result.GetCategoryCount(MetamorphicCategory::CodeGeneration));

    result.Clear();

    EXPECT_TRUE(result.filePath.empty());
    EXPECT_EQ(0u, result.processId);
    EXPECT_TRUE(result.sha256Hash.empty());
    EXPECT_EQ(0u, result.fileSize);
    EXPECT_FALSE(result.isMetamorphic);
    EXPECT_DOUBLE_EQ(0.0, result.mutationScore);
    EXPECT_EQ(MetamorphicSeverity::Low, result.maxSeverity);
    EXPECT_EQ(0u, result.totalDetections);
    EXPECT_EQ(0u, result.detectedCategories);
    EXPECT_TRUE(result.detectedTechniques.empty());
    EXPECT_TRUE(result.fuzzyHash.empty());
    EXPECT_TRUE(result.tlshHash.empty());
    EXPECT_TRUE(result.ngramProfile.empty());
    EXPECT_FALSE(result.similarityAnalysisComplete);
    EXPECT_FALSE(result.analysisComplete);
    EXPECT_FALSE(result.fromCache);
}

TEST(MetamorphicDetector_Statistics, ResetClearsDetectionAndCategoryCounters) {
    MetamorphicDetector::Statistics stats;
    stats.totalAnalyses = 6;
    stats.detections = 5;
    stats.metamorphicDetections = 4;
    stats.polymorphicDetections = 3;
    stats.packerDetections = 2;
    stats.familyMatches = 1;
    stats.cacheHits = 7;
    stats.cacheMisses = 8;
    stats.analysisErrors = 2;
    stats.totalAnalysisTimeUs = 12000;
    stats.bytesAnalyzed = 8192;
    stats.categoryDetections[static_cast<size_t>(MetamorphicCategory::Obfuscation)] = 3;

    stats.Reset();

    EXPECT_EQ(0u, stats.totalAnalyses.load());
    EXPECT_EQ(0u, stats.detections.load());
    EXPECT_EQ(0u, stats.metamorphicDetections.load());
    EXPECT_EQ(0u, stats.polymorphicDetections.load());
    EXPECT_EQ(0u, stats.packerDetections.load());
    EXPECT_EQ(0u, stats.familyMatches.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.analysisErrors.load());
    EXPECT_EQ(0u, stats.totalAnalysisTimeUs.load());
    EXPECT_EQ(0u, stats.bytesAnalyzed.load());
    EXPECT_EQ(0u, stats.categoryDetections[static_cast<size_t>(MetamorphicCategory::Obfuscation)].load());
}

} // namespace ShadowStrike::AntiEvasion::Tests
