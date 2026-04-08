/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PackerUnpacker deterministic behavior.
 *
 * Scope:
 *   - validation helpers, entropy utilities, and supported-packer metadata
 *   - statistics reset behavior
 *   - safe defaults from all major APIs before initialization
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string_view>

#include "../../../src/Shared_modules/Core/Engine/EmulationEngine.hpp"
#include "../../../src/Shared_modules/Core/Engine/PackerUnpacker.hpp"

namespace Engine = ShadowStrike::Core::Engine;

namespace ShadowStrike::Core::Engine::Test {
namespace {

bool Contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

}  // namespace

class PackerUnpackerTest : public ::testing::Test {
protected:
    void SetUp() override {
        Engine::PackerUnpacker::Instance().Shutdown();
    }

    void TearDown() override {
        Engine::PackerUnpacker::Instance().Shutdown();
    }
};

TEST_F(PackerUnpackerTest, ErrorAndOptionHelpersEnforceSafeBounds) {
    Engine::UnpackError error;
    EXPECT_FALSE(error.HasError());
    error.win32Code = ERROR_ACCESS_DENIED;
    error.message = L"denied";
    EXPECT_TRUE(error.HasError());
    error.Clear();
    EXPECT_FALSE(error.HasError());

    Engine::UnpackResult unpackResult;
    unpackResult.status = Engine::UnpackStatus::Success;
    EXPECT_TRUE(unpackResult.IsSuccess());
    unpackResult.status = Engine::UnpackStatus::PartialSuccess;
    EXPECT_TRUE(unpackResult.IsSuccess());
    unpackResult.status = Engine::UnpackStatus::Error;
    EXPECT_FALSE(unpackResult.IsSuccess());

    Engine::UnpackOptions options;
    EXPECT_TRUE(options.IsValid());
    EXPECT_EQ(options.MaxEmulationTimeMs(), options.timeoutSeconds * 1000u);

    options.timeoutSeconds = 0;
    EXPECT_TRUE(options.IsValid());

    options.maxLayers = 0;
    EXPECT_FALSE(options.IsValid());

    options.maxLayers = Engine::UnpackerConstants::MAX_UNPACKING_LAYERS + 1;
    EXPECT_FALSE(options.IsValid());

    Engine::PackerUnpackerConfiguration config;
    EXPECT_TRUE(config.IsValid());
    config.workerThreads = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxConcurrentUnpacks = 0;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(PackerUnpackerTest, StatisticsAndUtilityFunctionsRemainDeterministic) {
    Engine::PackerUnpacker::Statistics stats;
    stats.totalUnpackAttempts.store(7, std::memory_order_relaxed);
    stats.successfulUnpacks.store(3, std::memory_order_relaxed);
    stats.failedUnpacks.store(1, std::memory_order_relaxed);
    stats.packersDetected.store(4, std::memory_order_relaxed);
    stats.staticUnpacks.store(2, std::memory_order_relaxed);
    stats.dynamicUnpacks.store(5, std::memory_order_relaxed);
    stats.oepsFound.store(3, std::memory_order_relaxed);
    stats.importsReconstructed.store(2, std::memory_order_relaxed);
    stats.Reset();
    EXPECT_EQ(stats.totalUnpackAttempts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.successfulUnpacks.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.failedUnpacks.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.packersDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.staticUnpacks.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.dynamicUnpacks.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.oepsFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.importsReconstructed.load(std::memory_order_relaxed), 0u);

    const std::array<uint8_t, 256> highEntropy = [] {
        std::array<uint8_t, 256> values{};
        for (size_t i = 0; i < values.size(); ++i) {
            values[i] = static_cast<uint8_t>(i);
        }
        return values;
    }();
    const float entropy = Engine::CalculateSectionEntropy(highEntropy);
    EXPECT_GT(entropy, 7.9f);
    EXPECT_TRUE(Engine::IsHighEntropySection(entropy));
    EXPECT_FALSE(Engine::IsHighEntropySection(7.0f));
    EXPECT_FALSE(Engine::IsHighEntropySection(1.5f));

    const auto supportedPackers = Engine::PackerUnpacker::Instance().GetSupportedPackers();
    ASSERT_EQ(supportedPackers.size(), 12u);
    EXPECT_EQ(supportedPackers.front(), "UPX (static + dynamic)");
    EXPECT_EQ(supportedPackers.back(), "Custom/Unknown (dynamic via emulation)");
    EXPECT_TRUE(Contains(Engine::PackerUnpacker::GetVersionString(), "3.0."));
}

TEST_F(PackerUnpackerTest, GuardPathsReturnSafeDefaultsBeforeInitialization) {
    auto& unpacker = Engine::PackerUnpacker::Instance();
    EXPECT_FALSE(unpacker.IsInitialized());

    const std::vector<uint8_t> sample = {0x4D, 0x5A, 0x90, 0x00};
    const Engine::PackerDetectionResult detection = unpacker.DetectPacker(sample);
    EXPECT_FALSE(detection.isPacked);
    EXPECT_EQ(detection.packerType, Engine::PackerType::Unknown);
    EXPECT_TRUE(detection.packerName.empty());
    EXPECT_FLOAT_EQ(detection.confidence, 0.0f);
    EXPECT_EQ(detection.estimatedLayers, 0u);

    const Engine::UnpackResult unpackFileResult = unpacker.UnpackFile(L"C:\\missing.exe");
    EXPECT_EQ(unpackFileResult.status, Engine::UnpackStatus::Error);

    const Engine::UnpackResult staticResult =
        unpacker.StaticUnpack(sample, Engine::PackerType::UPX);
    EXPECT_EQ(staticResult.status, Engine::UnpackStatus::Error);

    const Engine::UnpackResult dynamicResult = unpacker.DynamicUnpack(sample);
    EXPECT_EQ(dynamicResult.status, Engine::UnpackStatus::Error);

    EXPECT_FALSE(unpacker.FindOEP(sample).has_value());
    EXPECT_FALSE(unpacker.ReconstructImports(sample).has_value());
    EXPECT_FALSE(unpacker.FixPEHeaders(sample, 0x1000).has_value());
    EXPECT_TRUE(unpacker.ExtractArchive(L"C:\\missing.zip").empty());
}

}  // namespace ShadowStrike::Core::Engine::Test
