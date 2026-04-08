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

} // namespace ShadowStrike::AntiEvasion::Tests
