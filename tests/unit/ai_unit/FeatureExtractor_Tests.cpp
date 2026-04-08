/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Comprehensive unit coverage for PhantomCortex feature extraction.
 *
 * Focus:
 *   - malformed input rejection
 *   - feature-vector dimensional guarantees
 *   - deterministic encoding of high-signal telemetry features
 *   - truncation and normalization semantics
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <numeric>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/AI/FeatureExtractor.hpp"
#include "AI_TestUtils.hpp"

namespace ShadowStrike::AI::Test {

namespace {

constexpr size_t kStaticByteHistogramOffset = 0;
constexpr size_t kStaticByteEntropyOffset = 256;
constexpr size_t kStringOffset = 512;
constexpr size_t kGeneralInfoOffset = 616;

std::vector<uint8_t> BuildRichPeSample() {
    std::vector<uint8_t> payload(4096, 0x90);
    size_t cursor = 0;

    const auto appendAscii = [&](std::string_view text) {
        if (cursor + text.size() + 1 >= payload.size()) {
            throw std::runtime_error("PE payload fixture overflow");
        }
        std::copy(text.begin(), text.end(), payload.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor += text.size();
        payload[cursor++] = 0x00;
    };

    appendAscii("https://evil.example/powershell");
    appendAscii("C:\\Temp\\cmd.exe");
    appendAscii("HKLM\\Software\\ShadowStrike");
    appendAscii("10.20.30.40");
    appendAscii("MZHEADER");
    appendAscii("CreateRemoteThread");

    MinimalPeOptions options;
    options.sectionPayload = std::move(payload);
    options.hasDebugDirectory = true;
    options.hasBaseRelocations = true;
    options.hasResources = true;
    options.hasSignature = true;
    options.hasTls = true;
    options.hasExports = true;

    return BuildMinimalPe32(options);
}

}  // namespace

class FeatureExtractorTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(FeatureExtractor::Instance().Initialize());
    }
};

TEST_F(FeatureExtractorTest, InstanceReturnsStableSingletonReference) {
    auto& first = FeatureExtractor::Instance();
    auto& second = FeatureExtractor::Instance();

    EXPECT_EQ(&first, &second);
}

TEST_F(FeatureExtractorTest, InitializeIsIdempotent) {
    EXPECT_TRUE(FeatureExtractor::Instance().Initialize());
    EXPECT_TRUE(FeatureExtractor::Instance().Initialize());
}

TEST_F(FeatureExtractorTest, ExtractPEFeaturesRejectsMalformedInputs) {
    auto& extractor = FeatureExtractor::Instance();

    EXPECT_FALSE(extractor.ExtractPEFeatures({}).has_value());

    const std::vector<uint8_t> tooSmall(16, 0x00);
    EXPECT_FALSE(extractor.ExtractPEFeatures(tooSmall).has_value());

    std::vector<uint8_t> invalidDos = BuildMinimalPe32();
    invalidDos[0] = 0x00;
    invalidDos[1] = 0x00;
    EXPECT_FALSE(extractor.ExtractPEFeatures(invalidDos).has_value());

    std::vector<uint8_t> invalidPeSignature = BuildMinimalPe32();
    invalidPeSignature[0x80] = 0x00;
    invalidPeSignature[0x81] = 0x00;
    invalidPeSignature[0x82] = 0x00;
    invalidPeSignature[0x83] = 0x00;
    EXPECT_FALSE(extractor.ExtractPEFeatures(invalidPeSignature).has_value());
}

TEST_F(FeatureExtractorTest, ExtractPEFeaturesRejectsInvalidOffsetsSectionCountsAndOptionalMagic) {
    auto& extractor = FeatureExtractor::Instance();

    std::vector<uint8_t> invalidLfanew = BuildMinimalPe32();
    PEParser::DosHeader dosHeader{};
    std::memcpy(&dosHeader, invalidLfanew.data(), sizeof(dosHeader));
    dosHeader.e_lfanew = static_cast<int32_t>(PEParser::MIN_LFANEW - 1);
    WriteStruct(invalidLfanew, 0, dosHeader);
    EXPECT_FALSE(extractor.ExtractPEFeatures(invalidLfanew).has_value());

    std::vector<uint8_t> tooManySections = BuildMinimalPe32();
    constexpr size_t kPeOffset = 0x80;
    constexpr size_t kFileHeaderOffset = kPeOffset + sizeof(uint32_t);
    PEParser::FileHeader fileHeader{};
    std::memcpy(&fileHeader,
                tooManySections.data() + static_cast<std::ptrdiff_t>(kFileHeaderOffset),
                sizeof(fileHeader));
    fileHeader.NumberOfSections = static_cast<uint16_t>(PEParser::Limits::MAX_SECTIONS + 1);
    WriteStruct(tooManySections, kFileHeaderOffset, fileHeader);
    EXPECT_FALSE(extractor.ExtractPEFeatures(tooManySections).has_value());

    std::vector<uint8_t> invalidOptionalMagic = BuildMinimalPe32();
    constexpr size_t kOptionalHeaderOffset =
        kFileHeaderOffset + sizeof(PEParser::FileHeader);
    const uint16_t badMagic = 0xDEAD;
    WriteStruct(invalidOptionalMagic, kOptionalHeaderOffset, badMagic);
    EXPECT_FALSE(extractor.ExtractPEFeatures(invalidOptionalMagic).has_value());
}

TEST_F(FeatureExtractorTest, ExtractPEFeaturesProducesDeterministicHighSignalFeatures) {
    auto features = FeatureExtractor::Instance().ExtractPEFeatures(BuildRichPeSample());
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::STATIC_FEATURE_COUNT);

    const float byteHistogramSum = std::accumulate(
        features->begin() + static_cast<std::ptrdiff_t>(kStaticByteHistogramOffset),
        features->begin() + static_cast<std::ptrdiff_t>(kStaticByteHistogramOffset + 256),
        0.0f);
    EXPECT_NEAR(byteHistogramSum, 1.0f, 1e-5f);

    const float entropyHistogramSum = std::accumulate(
        features->begin() + static_cast<std::ptrdiff_t>(kStaticByteEntropyOffset),
        features->begin() + static_cast<std::ptrdiff_t>(kStaticByteEntropyOffset + 256),
        0.0f);
    EXPECT_NEAR(entropyHistogramSum, 1.0f, 1e-5f);

    EXPECT_GT((*features)[kStringOffset + 0], 0.0f);
    EXPECT_GT((*features)[kStringOffset + 2], 0.0f);
    EXPECT_GT((*features)[kStringOffset + 3], 0.0f);
    EXPECT_GT((*features)[kStringOffset + 4], 0.0f);
    EXPECT_GT((*features)[kStringOffset + 5], 0.0f);
    EXPECT_GT((*features)[kStringOffset + 6], 0.0f);

    constexpr size_t kCmdExeIndex = kStringOffset + 12;
    constexpr size_t kPowershellIndex = kStringOffset + 13;
    constexpr size_t kCreateRemoteThreadIndex = kStringOffset + 15;
    EXPECT_GT((*features)[kCmdExeIndex], 0.0f);
    EXPECT_GT((*features)[kPowershellIndex], 0.0f);
    EXPECT_GT((*features)[kCreateRemoteThreadIndex], 0.0f);

    EXPECT_GT((*features)[kGeneralInfoOffset + 0], 0.0f);
    EXPECT_FLOAT_EQ((*features)[kGeneralInfoOffset + 1], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kGeneralInfoOffset + 2], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kGeneralInfoOffset + 4], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kGeneralInfoOffset + 5], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kGeneralInfoOffset + 6], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kGeneralInfoOffset + 7], 1.0f);
}

TEST_F(FeatureExtractorTest, ExtractBehavioralFeaturesRejectsEmptyInput) {
    EXPECT_FALSE(FeatureExtractor::Instance().ExtractBehavioralFeatures({}).has_value());
}

TEST_F(FeatureExtractorTest, ExtractBehavioralFeaturesUsesMostRecentCallsAndNormalizesFields) {
    std::vector<APICallRecord> calls(130);
    for (size_t i = 0; i < calls.size(); ++i) {
        calls[i].apiNameHash = static_cast<uint32_t>(1000 + i);
        calls[i].argSummaryHash = static_cast<uint32_t>(2000 + i);
        calls[i].returnValue = static_cast<int32_t>(i);
        calls[i].timestampDeltaMs = static_cast<float>(i);
    }

    auto features = FeatureExtractor::Instance().ExtractBehavioralFeatures(calls);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::BEHAVIORAL_FEATURE_COUNT);

    constexpr float kHashNorm = 1.0f / static_cast<float>(UINT32_MAX);
    constexpr float kRetNorm = 1.0f / static_cast<float>(INT32_MAX);

    EXPECT_NEAR((*features)[0], static_cast<float>(1002u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[1], static_cast<float>(2002u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[2], 2.0f * kRetNorm, 1e-9f);
    EXPECT_NEAR((*features)[3], std::log1pf(2.0f), 1e-6f);

    const size_t lastBase = (128u - 1u) * 4u;
    EXPECT_NEAR((*features)[lastBase + 0], static_cast<float>(1129u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[lastBase + 1], static_cast<float>(2129u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[lastBase + 2], 129.0f * kRetNorm, 1e-9f);
    EXPECT_NEAR((*features)[lastBase + 3], std::log1pf(129.0f), 1e-6f);
}

TEST_F(FeatureExtractorTest, ExtractBehavioralFeaturesClampsExtremeReturnValuesAndNegativeTimestamps) {
    const std::array<APICallRecord, 2> calls = {{
        {0xAAAAAAAAu, 0x11111111u, std::numeric_limits<int32_t>::max(), -5.0f},
        {0xBBBBBBBBu, 0x22222222u, std::numeric_limits<int32_t>::min(), -0.25f},
    }};

    auto features = FeatureExtractor::Instance().ExtractBehavioralFeatures(calls);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::BEHAVIORAL_FEATURE_COUNT);

    EXPECT_FLOAT_EQ((*features)[2], 1.0f);
    EXPECT_FLOAT_EQ((*features)[3], 0.0f);
    EXPECT_FLOAT_EQ((*features)[6], -1.0f);
    EXPECT_FLOAT_EQ((*features)[7], 0.0f);
}

TEST_F(FeatureExtractorTest, ExtractMemoryFeaturesRejectsEmptyRegion) {
    MemoryRegionInfo region{};
    EXPECT_FALSE(FeatureExtractor::Instance().ExtractMemoryFeatures(region).has_value());
}

TEST_F(FeatureExtractorTest, ExtractMemoryFeaturesEncodesHeuristicsAndProtectionFlags) {
    std::vector<uint8_t> regionData(256, 0x00);
    std::fill(regionData.begin(), regionData.begin() + 64, static_cast<uint8_t>(0x90));
    std::fill(regionData.begin() + 64, regionData.begin() + 128, static_cast<uint8_t>('A'));
    std::fill(regionData.begin() + 192, regionData.end(), static_cast<uint8_t>(0xC3));

    MemoryRegionInfo region{};
    region.data = regionData;
    region.baseAddress = 0x13370000;
    region.size = regionData.size();
    region.protection = 0x140;  // PAGE_EXECUTE_READWRITE | PAGE_GUARD

    auto features = FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::MEMORY_FEATURE_COUNT);

    constexpr size_t kEntropyIndex = 32;
    constexpr size_t kInstructionDensityIndex = 33;
    constexpr size_t kNopSledIndex = 34;
    constexpr size_t kNullRatioIndex = 35;
    constexpr size_t kPrintableRatioIndex = 36;
    constexpr size_t kAlignmentIndex = 37;
    constexpr size_t kRopDensityIndex = 38;
    constexpr size_t kReadFlagIndex = 40;
    constexpr size_t kWriteFlagIndex = 41;
    constexpr size_t kExecuteFlagIndex = 42;
    constexpr size_t kGuardFlagIndex = 43;

    EXPECT_GT((*features)[kEntropyIndex], 0.0f);
    EXPECT_GT((*features)[kInstructionDensityIndex], 0.9f);
    EXPECT_NEAR((*features)[kNopSledIndex], 0.25f, 1e-6f);
    EXPECT_NEAR((*features)[kNullRatioIndex], 0.25f, 1e-6f);
    EXPECT_NEAR((*features)[kPrintableRatioIndex], 0.25f, 1e-6f);
    EXPECT_FLOAT_EQ((*features)[kAlignmentIndex], 0.5f);
    EXPECT_NEAR((*features)[kRopDensityIndex], 0.25f, 1e-6f);
    EXPECT_FLOAT_EQ((*features)[kReadFlagIndex], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kWriteFlagIndex], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kExecuteFlagIndex], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kGuardFlagIndex], 1.0f);
}

TEST_F(FeatureExtractorTest, ExtractNetworkFeaturesUsesOtherBucketAndStableZerosForEmptyTraffic) {
    NetworkFlowInfo flow{};
    flow.protocol = 1;
    flow.srcPort = 65000;
    flow.dstPort = 65001;

    auto features = FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::NETWORK_FEATURE_COUNT);

    EXPECT_FLOAT_EQ((*features)[4], 0.0f);
    EXPECT_FLOAT_EQ((*features)[5], 0.0f);
    EXPECT_FLOAT_EQ((*features)[6], 0.0f);
    EXPECT_FLOAT_EQ((*features)[7], 0.0f);
    EXPECT_FLOAT_EQ((*features)[8], 0.0f);
    EXPECT_FLOAT_EQ((*features)[9], 1.0f);
    EXPECT_FLOAT_EQ((*features)[14], 0.0f);
    EXPECT_FLOAT_EQ((*features)[15], 0.0f);
    EXPECT_FLOAT_EQ((*features)[18], 0.0f);
    EXPECT_FLOAT_EQ((*features)[30], 0.0f);
    EXPECT_FLOAT_EQ((*features)[31], 1.0f);
    EXPECT_FLOAT_EQ((*features)[33], 0.0f);
    EXPECT_FLOAT_EQ((*features)[34], 0.0f);
}

TEST_F(FeatureExtractorTest, ExtractNetworkFeaturesPrioritizesApplicationPortsOverTransportProtocol) {
    NetworkFlowInfo flow{};
    flow.protocol = 6;
    flow.dstPort = 53;

    auto features = FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::NETWORK_FEATURE_COUNT);

    EXPECT_FLOAT_EQ((*features)[4], 0.0f);
    EXPECT_FLOAT_EQ((*features)[6], 1.0f);
    EXPECT_FLOAT_EQ((*features)[9], 0.0f);
}

TEST_F(FeatureExtractorTest, ExtractNetworkFeaturesEncodesProtocolRatiosAndRates) {
    NetworkFlowInfo flow{};
    flow.srcIPv4 = 0x0A000001;
    flow.dstIPv4 = 0xC0A8010A;
    flow.srcPort = 51515;
    flow.dstPort = 443;
    flow.protocol = 6;
    flow.bytesSent = 900;
    flow.bytesReceived = 100;
    flow.packetsSent = 9;
    flow.packetsReceived = 1;
    flow.durationMs = 1000.0f;
    flow.avgInterArrivalMs = 100.0f;
    flow.stdInterArrivalMs = 10.0f;
    flow.minInterArrivalMs = 90.0f;
    flow.maxInterArrivalMs = 110.0f;
    flow.ja3Hash = 0x01020304;
    flow.ja3sHash = 0x05060708;
    flow.dnsQueryHash = 0x090A0B0C;
    flow.dnsQueryCount = 3;
    flow.tlsVersion = 0x0303;
    flow.payloadEntropy = 7.5f;
    flow.uniquePayloadBytes = 200;

    auto features = FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::NETWORK_FEATURE_COUNT);

    EXPECT_FLOAT_EQ((*features)[8], 1.0f);
    EXPECT_NEAR((*features)[14], 0.9f, 1e-6f);
    EXPECT_NEAR((*features)[15], 0.9f, 1e-6f);
    EXPECT_NEAR((*features)[18], std::log1pf(1000.0f), 1e-6f);
    EXPECT_NEAR((*features)[26], std::log1pf(3.0f), 1e-6f);
    EXPECT_FLOAT_EQ((*features)[28], 7.5f);
    EXPECT_NEAR((*features)[29], 200.0f / 256.0f, 1e-6f);
    EXPECT_NEAR((*features)[30], 0.1f / 10.0f, 1e-6f);
    EXPECT_NEAR((*features)[31], 1.0f - (0.1f / 10.0f), 1e-6f);
    EXPECT_NEAR((*features)[33], std::log1pf(10.0f), 1e-6f);
    EXPECT_NEAR((*features)[34], std::log1pf(1000.0f), 1e-6f);
}

TEST_F(FeatureExtractorTest, ExtractEmulationFeaturesRejectsEmptyTrace) {
    EXPECT_FALSE(FeatureExtractor::Instance().ExtractEmulationFeatures({}).has_value());
}

TEST_F(FeatureExtractorTest, ExtractEmulationFeaturesBuildsHistogramsAndTemporalWindows) {
    const std::array<EmulationEvent, 4> events = {{
        {1, 0, 42, 0b00000011},
        {1, 1, 42, 0b00000010},
        {2, 1, 7,  0b00000100},
        {3, 3, 0,  0b00000000},
    }};

    auto features = FeatureExtractor::Instance().ExtractEmulationFeatures(events);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::EMULATION_FEATURE_COUNT);

    EXPECT_NEAR((*features)[1], 0.50f, 1e-6f);
    EXPECT_NEAR((*features)[2], 0.25f, 1e-6f);
    EXPECT_NEAR((*features)[3], 0.25f, 1e-6f);

    EXPECT_NEAR((*features)[16], 0.25f, 1e-6f);
    EXPECT_NEAR((*features)[17], 0.50f, 1e-6f);
    EXPECT_NEAR((*features)[19], 0.25f, 1e-6f);

    EXPECT_NEAR((*features)[20], 0.50f, 1e-6f);
    EXPECT_NEAR((*features)[21], 0.25f, 1e-6f);

    constexpr size_t kEflagsOffset = 120;
    EXPECT_NEAR((*features)[kEflagsOffset + 0], 0.25f, 1e-6f);
    EXPECT_NEAR((*features)[kEflagsOffset + 1], 0.50f, 1e-6f);
    EXPECT_NEAR((*features)[kEflagsOffset + 2], 0.25f, 1e-6f);

    const float ngramSum = std::accumulate(features->begin() + 128, features->begin() + 256, 0.0f);
    EXPECT_GT(ngramSum, 0.0f);

    constexpr size_t kTemporalOffset = 256;
    EXPECT_FLOAT_EQ((*features)[kTemporalOffset + 0], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kTemporalOffset + 1], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kTemporalOffset + 2], 1.0f);
    EXPECT_FLOAT_EQ((*features)[kTemporalOffset + 3], 1.0f);
}

TEST_F(FeatureExtractorTest, ExtractEmulationFeaturesWithSingleEventLeavesNgramsEmpty) {
    const std::array<EmulationEvent, 1> events = {{{15, 3, 99, 0b00000101}}};

    auto features = FeatureExtractor::Instance().ExtractEmulationFeatures(events);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::EMULATION_FEATURE_COUNT);

    EXPECT_FLOAT_EQ((*features)[15], 1.0f);
    EXPECT_FLOAT_EQ((*features)[16 + 3], 1.0f);
    EXPECT_FLOAT_EQ((*features)[20], 1.0f);
    EXPECT_FLOAT_EQ((*features)[120 + 0], 1.0f);
    EXPECT_FLOAT_EQ((*features)[120 + 2], 1.0f);

    const float ngramSum = std::accumulate(features->begin() + 128, features->begin() + 256, 0.0f);
    EXPECT_FLOAT_EQ(ngramSum, 0.0f);
    EXPECT_FLOAT_EQ((*features)[256], 1.0f);
    EXPECT_FLOAT_EQ((*features)[257], 0.0f);
}

}  // namespace ShadowStrike::AI::Test
