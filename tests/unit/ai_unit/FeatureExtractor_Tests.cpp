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

#include "../../../src/PhantomCore/AI/FeatureExtractor.hpp"
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
    // Send 514 calls so the extractor truncates to the most recent 512.
    // With SEQ_LENGTH=512, startIdx = 514-512 = 2, so first slot = call[2].
    std::vector<APICallRecord> calls(514);
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

    // First slot encodes call[2] (startIdx=2).
    EXPECT_NEAR((*features)[0], static_cast<float>(1002u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[1], static_cast<float>(2002u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[2], 2.0f * kRetNorm, 1e-9f);
    EXPECT_NEAR((*features)[3], std::log1pf(2.0f), 1e-6f);

    // Last slot (index 511) encodes call[2+511] = call[513].
    const size_t lastBase = (512u - 1u) * 4u;
    EXPECT_NEAR((*features)[lastBase + 0], static_cast<float>(1513u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[lastBase + 1], static_cast<float>(2513u) * kHashNorm, 1e-9f);
    EXPECT_NEAR((*features)[lastBase + 2], 513.0f * kRetNorm, 1e-9f);
    EXPECT_NEAR((*features)[lastBase + 3], std::log1pf(513.0f), 1e-6f);
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

    // New layout: 16 compressed bins [0-15], then heuristics.
    constexpr size_t kEntropyIndex = 16;
    constexpr size_t kInstructionDensityIndex = 17;
    constexpr size_t kNopSledIndex = 18;
    constexpr size_t kNullRatioIndex = 19;
    constexpr size_t kPrintableRatioIndex = 20;
    constexpr size_t kAlignmentIndex = 21;
    constexpr size_t kRopDensityIndex = 22;
    // Index 23 = compression ratio, then protection flags.
    constexpr size_t kReadFlagIndex = 24;
    constexpr size_t kWriteFlagIndex = 25;
    constexpr size_t kExecuteFlagIndex = 26;
    constexpr size_t kGuardFlagIndex = 27;

    EXPECT_GT((*features)[kEntropyIndex], 0.0f);
    EXPECT_GT((*features)[kInstructionDensityIndex], 0.9f);
    EXPECT_NEAR((*features)[kNopSledIndex], 0.25f, 1e-6f);
    EXPECT_NEAR((*features)[kNullRatioIndex], 0.25f, 1e-6f);
    EXPECT_NEAR((*features)[kPrintableRatioIndex], 0.25f, 1e-6f);
    EXPECT_FLOAT_EQ((*features)[kAlignmentIndex], 0.75f);
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

TEST_F(FeatureExtractorTest, ExtractEmulationFeaturesBuildsSequenceEncoding) {
    // Emulation v2 uses flat sequence encoding: 1024 steps × 4 features per step.
    // Each event maps to [opcodeCat/15, memAccess/3, apiCallId/65535, eflags/255].
    const std::array<EmulationEvent, 4> events = {{
        {1, 0, 42, 0b00000011},
        {1, 1, 42, 0b00000010},
        {2, 1, 7,  0b00000100},
        {3, 3, 0,  0b00000000},
    }};

    auto features = FeatureExtractor::Instance().ExtractEmulationFeatures(events);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::EMULATION_FEATURE_COUNT);

    constexpr float kOpNorm   = 1.0f / 15.0f;
    constexpr float kMemNorm  = 1.0f / 3.0f;
    constexpr float kApiNorm  = 1.0f / 65535.0f;
    constexpr float kEfNorm   = 1.0f / 255.0f;

    // Event 0 at base=0
    EXPECT_NEAR((*features)[0], 1.0f * kOpNorm,  1e-6f);
    EXPECT_NEAR((*features)[1], 0.0f * kMemNorm, 1e-6f);
    EXPECT_NEAR((*features)[2], 42.0f * kApiNorm, 1e-6f);
    EXPECT_NEAR((*features)[3], 3.0f * kEfNorm,  1e-6f);

    // Event 1 at base=4
    EXPECT_NEAR((*features)[4], 1.0f * kOpNorm,  1e-6f);
    EXPECT_NEAR((*features)[5], 1.0f * kMemNorm, 1e-6f);
    EXPECT_NEAR((*features)[6], 42.0f * kApiNorm, 1e-6f);
    EXPECT_NEAR((*features)[7], 2.0f * kEfNorm,  1e-6f);

    // Event 2 at base=8
    EXPECT_NEAR((*features)[8],  2.0f * kOpNorm,  1e-6f);
    EXPECT_NEAR((*features)[9],  1.0f * kMemNorm, 1e-6f);
    EXPECT_NEAR((*features)[10], 7.0f * kApiNorm, 1e-6f);
    EXPECT_NEAR((*features)[11], 4.0f * kEfNorm,  1e-6f);

    // Event 3 at base=12
    EXPECT_NEAR((*features)[12], 3.0f * kOpNorm,  1e-6f);
    EXPECT_NEAR((*features)[13], 3.0f * kMemNorm, 1e-6f);
    EXPECT_FLOAT_EQ((*features)[14], 0.0f);
    EXPECT_FLOAT_EQ((*features)[15], 0.0f);

    // Beyond the 4 events, remaining features should be zero-padded.
    EXPECT_FLOAT_EQ((*features)[16], 0.0f);
    EXPECT_FLOAT_EQ((*features)[17], 0.0f);
    EXPECT_FLOAT_EQ((*features)[CortexConstants::EMULATION_FEATURE_COUNT - 1], 0.0f);
}

TEST_F(FeatureExtractorTest, ExtractEmulationFeaturesWithSingleEventPadsRemainder) {
    const std::array<EmulationEvent, 1> events = {{{15, 3, 99, 0b00000101}}};

    auto features = FeatureExtractor::Instance().ExtractEmulationFeatures(events);
    ASSERT_TRUE(features.has_value());
    ASSERT_EQ(features->size(), CortexConstants::EMULATION_FEATURE_COUNT);

    constexpr float kOpNorm  = 1.0f / 15.0f;
    constexpr float kMemNorm = 1.0f / 3.0f;
    constexpr float kApiNorm = 1.0f / 65535.0f;
    constexpr float kEfNorm  = 1.0f / 255.0f;

    // Single event at base=0: opcodeCategory 15 saturates to 1.0, memAccess 3 → 1.0.
    EXPECT_FLOAT_EQ((*features)[0], 15.0f * kOpNorm);  // 1.0
    EXPECT_FLOAT_EQ((*features)[1], 3.0f * kMemNorm);   // 1.0
    EXPECT_NEAR((*features)[2], 99.0f * kApiNorm, 1e-6f);
    EXPECT_NEAR((*features)[3], 5.0f * kEfNorm, 1e-6f);

    // All remaining slots are zero-padded.
    EXPECT_FLOAT_EQ((*features)[4], 0.0f);
    EXPECT_FLOAT_EQ((*features)[5], 0.0f);
    EXPECT_FLOAT_EQ((*features)[CortexConstants::EMULATION_FEATURE_COUNT - 1], 0.0f);
}

}  // namespace ShadowStrike::AI::Test
