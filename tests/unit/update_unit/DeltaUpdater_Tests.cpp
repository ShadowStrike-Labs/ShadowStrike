/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic DeltaUpdater contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Update/DeltaUpdater.hpp"

namespace ShadowStrike::Update::Test {
namespace {

using nlohmann::json;

void AppendU16(std::vector<uint8_t>& buffer, uint16_t value) {
    buffer.push_back(static_cast<uint8_t>(value & 0xFFu));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void AppendU32(std::vector<uint8_t>& buffer, uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        buffer.push_back(static_cast<uint8_t>((value >> shift) & 0xFFu));
    }
}

void AppendU64(std::vector<uint8_t>& buffer, uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        buffer.push_back(static_cast<uint8_t>((value >> shift) & 0xFFu));
    }
}

[[nodiscard]] std::vector<uint8_t> SerializeHeaderForDetection(const PatchHeader& header) {
    std::vector<uint8_t> bytes;
    bytes.reserve(96);
    AppendU32(bytes, header.magic);
    AppendU16(bytes, header.version);
    bytes.push_back(static_cast<uint8_t>(header.algorithm));
    bytes.push_back(header.flags);
    AppendU64(bytes, header.sourceSize);
    AppendU64(bytes, header.targetSize);
    AppendU64(bytes, header.patchSize);
    bytes.insert(bytes.end(), header.sourceChecksum.begin(), header.sourceChecksum.end());
    bytes.insert(bytes.end(), header.targetChecksum.begin(), header.targetChecksum.end());
    return bytes;
}

}  // namespace

TEST(DeltaUpdaterTest, HelperNamesDetectionAndSizingRemainStable) {
    EXPECT_EQ(GetAlgorithmName(PatchAlgorithm::BSDiff), "BSDiff");
    EXPECT_EQ(GetPatchStateName(PatchState::Completed), "Completed");
    EXPECT_EQ(GetAlgorithmName(static_cast<PatchAlgorithm>(0xFF)), "Unknown");
    EXPECT_EQ(GetPatchStateName(static_cast<PatchState>(0xFF)), "Unknown");

    const std::string versionString = DeltaUpdater::GetVersionString();
    EXPECT_FALSE(versionString.empty());
    EXPECT_EQ(std::count(versionString.begin(), versionString.end(), '.'), 2);

    PatchHeader header;
    header.algorithm = PatchAlgorithm::XDelta3;
    header.sourceSize = 1024;
    header.targetSize = 4096;
    header.patchSize = 512;

    EXPECT_EQ(DetectAlgorithm(SerializeHeaderForDetection(header)), PatchAlgorithm::XDelta3);
    EXPECT_EQ(DetectAlgorithm(std::vector<uint8_t>{0x01, 0x02, 0x03}), PatchAlgorithm::Auto);
    EXPECT_EQ(EstimatePatchSize(1000, 2000), 760u);
}

TEST(DeltaUpdaterTest, HeaderValidationDtosAndStatisticsRemainActionable) {
    PatchHeader valid;
    valid.version = 2;
    valid.algorithm = PatchAlgorithm::BSDiff;
    valid.flags = 7;
    valid.sourceSize = 8192;
    valid.targetSize = 9216;
    valid.patchSize = 512;
    for (size_t index = 0; index < valid.sourceChecksum.size(); ++index) {
        valid.sourceChecksum[index] = static_cast<uint8_t>(index);
        valid.targetChecksum[index] = static_cast<uint8_t>(index + 1);
    }

    EXPECT_TRUE(valid.IsValid());

    PatchHeader invalid = valid;
    invalid.magic = 0;
    EXPECT_FALSE(invalid.IsValid());

    invalid = valid;
    invalid.version = 0;
    EXPECT_FALSE(invalid.IsValid());

    invalid = valid;
    invalid.algorithm = static_cast<PatchAlgorithm>(99);
    EXPECT_FALSE(invalid.IsValid());

    invalid = valid;
    invalid.sourceSize =
        (static_cast<uint64_t>(DeltaConstants::MAX_FILE_SIZE_GB) * 1024ull * 1024ull * 1024ull) + 1ull;
    EXPECT_FALSE(invalid.IsValid());

    invalid = valid;
    invalid.patchSize =
        (static_cast<uint64_t>(DeltaConstants::MAX_PATCH_SIZE_MB) * 1024ull * 1024ull) + 1ull;
    EXPECT_FALSE(invalid.IsValid());

    const json headerJson = json::parse(valid.ToJson());
    EXPECT_EQ(headerJson.at("magic"), DeltaConstants::PATCH_MAGIC);
    EXPECT_EQ(headerJson.at("algorithm"), static_cast<int>(PatchAlgorithm::BSDiff));
    EXPECT_EQ(headerJson.at("patchSize"), 512);

    PatchInfo info;
    info.patchPath = "update.delta";
    info.header = valid;
    info.sourceFile = "source.bin";
    info.targetFile = "target.bin";
    info.compressionRatio = 0.42;
    info.estimatedMemory = 16384;

    const json infoJson = json::parse(info.ToJson());
    EXPECT_EQ(infoJson.at("patchPath"), "update.delta");
    EXPECT_EQ(infoJson.at("sourceFile"), "source.bin");
    EXPECT_EQ(infoJson.at("estimatedMemory"), 16384);

    PatchProgress progress;
    progress.state = PatchState::Patching;
    progress.progressPercent = 88;
    progress.bytesProcessed = 4096;
    progress.totalBytes = 8192;
    progress.currentOperation = "Applying delta";
    progress.speedBps = 1024;
    progress.etaSeconds = 4;

    const json progressJson = json::parse(progress.ToJson());
    EXPECT_EQ(progressJson.at("state"), static_cast<int>(PatchState::Patching));
    EXPECT_EQ(progressJson.at("progressPercent"), 88);
    EXPECT_EQ(progressJson.at("currentOperation"), "Applying delta");

    PatchResult result;
    result.success = true;
    result.sourceFile = "source.bin";
    result.outputFile = "output.bin";
    result.algorithmUsed = PatchAlgorithm::Courgette;
    result.bytesSaved = 3072;
    result.durationMs = 15;
    result.outputVerified = true;
    result.errorMessage = "none";

    const json resultJson = json::parse(result.ToJson());
    EXPECT_TRUE(resultJson.at("success").get<bool>());
    EXPECT_EQ(resultJson.at("algorithmUsed"), static_cast<int>(PatchAlgorithm::Courgette));
    EXPECT_TRUE(resultJson.at("outputVerified").get<bool>());

    DeltaStatistics stats;
    stats.patchesApplied = 9;
    stats.patchesFailed = 2;
    stats.bytesProcessed = 12345;
    stats.bytesSaved = 6789;
    stats.totalDurationMs = 55;
    stats.byAlgorithm[static_cast<size_t>(PatchAlgorithm::Courgette)] = 3;

    stats.Reset();

    EXPECT_EQ(stats.patchesApplied, 0u);
    EXPECT_EQ(stats.patchesFailed, 0u);
    EXPECT_EQ(stats.bytesProcessed, 0u);
    EXPECT_EQ(stats.byAlgorithm[static_cast<size_t>(PatchAlgorithm::Courgette)], 0u);

    const json statsJson = json::parse(stats.ToJson());
    EXPECT_EQ(statsJson.at("patchesApplied"), 0);
    EXPECT_EQ(statsJson.at("patchesFailed"), 0);
    EXPECT_TRUE(statsJson.at("byAlgorithm").is_array());

    DeltaUpdaterConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.maxPatchSizeMB = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxFileSizeGB = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.streamBufferSize = 1024;
    EXPECT_FALSE(config.IsValid());
}

TEST(DeltaUpdaterTest, BoundaryValidationAndDefaultRuntimeStateFailClosed) {
    PatchHeader maxValid;
    maxValid.version = 10;
    maxValid.algorithm = PatchAlgorithm::XDelta3;
    maxValid.sourceSize =
        static_cast<uint64_t>(DeltaConstants::MAX_FILE_SIZE_GB) * 1024ull * 1024ull * 1024ull;
    maxValid.targetSize = maxValid.sourceSize;
    maxValid.patchSize =
        static_cast<uint64_t>(DeltaConstants::MAX_PATCH_SIZE_MB) * 1024ull * 1024ull;
    EXPECT_TRUE(maxValid.IsValid());

    PatchHeader invalid = maxValid;
    invalid.version = 11;
    EXPECT_FALSE(invalid.IsValid());

    invalid = maxValid;
    invalid.targetSize += 1;
    EXPECT_FALSE(invalid.IsValid());

    auto& updater = DeltaUpdater::Instance();
    updater.Shutdown();

    EXPECT_TRUE(DeltaUpdater::HasInstance());
    EXPECT_FALSE(updater.IsInitialized());
    EXPECT_EQ(updater.GetStatus(), DeltaUpdaterStatus::Uninitialized);
    EXPECT_EQ(updater.GetProgress().state, PatchState::NotStarted);
    EXPECT_EQ(updater.GetStatistics().patchesApplied, 0u);
    EXPECT_FALSE(updater.ValidatePatch(std::span<const uint8_t>{}));
    EXPECT_FALSE(updater.GetPatchInfo(L"missing.delta").has_value());

    const auto result = updater.ApplyPatchMemory(
        std::span<const uint8_t>{},
        std::span<const uint8_t>{});
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.errorMessage, "DeltaUpdater not initialized");
}

}  // namespace ShadowStrike::Update::Test
