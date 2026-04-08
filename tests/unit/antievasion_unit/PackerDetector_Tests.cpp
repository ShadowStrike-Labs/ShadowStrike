/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/AntiEvasion/PackerDetector.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(PackerDetector_Helpers, CategoryAndTypeStringMappingsRemainStable) {
    EXPECT_STREQ("Compression Packer", PackerCategoryToString(PackerCategory::Compression));
    EXPECT_STREQ("VM Protection", PackerCategoryToString(PackerCategory::VMProtection));
    EXPECT_STREQ("Unknown", PackerCategoryToString(static_cast<PackerCategory>(0xFF)));

    EXPECT_STREQ(L"UPX", PackerTypeToString(PackerType::UPX));
    EXPECT_STREQ(L"Themida", PackerTypeToString(PackerType::Themida));
    EXPECT_STREQ(L"VMProtect", PackerTypeToString(PackerType::VMProtect));
    EXPECT_STREQ(L"Custom Packer", PackerTypeToString(PackerType::Custom_Packer));
    EXPECT_STREQ(L"Unknown", PackerTypeToString(static_cast<PackerType>(0xFFFF)));
}

TEST(PackerDetector_Entropy, CalculateEntropyHandlesNullUniformAndHighEntropyBuffers) {
    std::vector<uint8_t> zeros(1024, 0x00);
    std::vector<uint8_t> alternating(1024);
    for (size_t i = 0; i < alternating.size(); ++i) {
        alternating[i] = static_cast<uint8_t>(i % 2 == 0 ? 0x00 : 0xFF);
    }

    std::vector<uint8_t> fullRange(256);
    for (size_t i = 0; i < fullRange.size(); ++i) {
        fullRange[i] = static_cast<uint8_t>(i);
    }

    EXPECT_DOUBLE_EQ(0.0, PackerDetector::CalculateEntropy(nullptr, 0));
    EXPECT_NEAR(0.0, PackerDetector::CalculateEntropy(zeros.data(), zeros.size()), 1e-9);
    EXPECT_NEAR(1.0, PackerDetector::CalculateEntropy(alternating.data(), alternating.size()), 0.05);
    EXPECT_NEAR(8.0, PackerDetector::CalculateEntropy(fullRange.data(), fullRange.size()), 0.05);
}

TEST(PackerDetector_Builder, MatchBuilderPopulatesDerivedMetadata) {
    const auto match = PackerMatchBuilder{}
        .Type(PackerType::VMProtect)
        .Method(DetectionMethod::EPSignature)
        .Confidence(0.99)
        .Name(L"VMProtect")
        .Version(L"3.x")
        .Pattern(L"vmprotect ep stub")
        .Location(0x420)
        .Details(L"Commercial virtualization protector stub detected")
        .Build();

    EXPECT_EQ(PackerType::VMProtect, match.packerType);
    EXPECT_EQ(GetPackerCategory(PackerType::VMProtect), match.category);
    EXPECT_EQ(GetPackerSeverity(PackerType::VMProtect), match.severity);
    EXPECT_STREQ(PackerTypeToMitreId(PackerType::VMProtect), match.mitreId.c_str());
    EXPECT_EQ(DetectionMethod::EPSignature, match.method);
    EXPECT_DOUBLE_EQ(0.99, match.confidence);
    EXPECT_EQ(L"VMProtect", match.packerName);
    EXPECT_EQ(L"3.x", match.version);
    EXPECT_EQ(L"vmprotect ep stub", match.matchedPattern);
    EXPECT_EQ(0x420u, match.matchLocation);
    EXPECT_EQ(L"Commercial virtualization protector stub detected", match.details);
}

TEST(PackerDetector_Statistics, ResetClearsCounters) {
    PackerDetector::Statistics stats;
    stats.totalAnalyses = 8;
    stats.packedFilesDetected = 6;
    stats.installersDetected = 1;
    stats.cryptersDetected = 2;
    stats.protectorsDetected = 3;
    stats.cacheHits = 4;
    stats.cacheMisses = 5;
    stats.analysisErrors = 1;
    stats.totalAnalysisTimeUs = 9000;
    stats.bytesAnalyzed = 4096;
    stats.categoryDetections[static_cast<size_t>(PackerCategory::Protector)] = 2;

    stats.Reset();

    EXPECT_EQ(0u, stats.totalAnalyses.load());
    EXPECT_EQ(0u, stats.packedFilesDetected.load());
    EXPECT_EQ(0u, stats.installersDetected.load());
    EXPECT_EQ(0u, stats.cryptersDetected.load());
    EXPECT_EQ(0u, stats.protectorsDetected.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.analysisErrors.load());
    EXPECT_EQ(0u, stats.totalAnalysisTimeUs.load());
    EXPECT_EQ(0u, stats.bytesAnalyzed.load());

    for (const auto& categoryCounter : stats.categoryDetections) {
        EXPECT_EQ(0u, categoryCounter.load());
    }
}

} // namespace ShadowStrike::AntiEvasion::Tests
