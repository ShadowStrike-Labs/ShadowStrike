/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Enterprise-grade unit coverage for PhantomCortex configuration handling.
 *
 * Focus:
 *   - input validation and path hardening
 *   - threshold and limit clamping
 *   - default preservation on partial loads
 *   - JSON persistence fidelity
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <cmath>
#include <filesystem>
#include <fstream>
#include <string>

#include "../../../src/Shared_modules/AI/CortexConfig.hpp"
#include "../../../src/Shared_modules/Utils/StringUtils.hpp"
#include "../../../include/nlohmann/json.hpp"
#include "AI_TestUtils.hpp"

namespace fs = std::filesystem;

namespace ShadowStrike::AI::Test {

namespace {

[[nodiscard]] std::string EscapeJsonString(std::string value) {
    size_t position = 0;
    while ((position = value.find('\\', position)) != std::string::npos) {
        value.insert(position, 1, '\\');
        position += 2;
    }

    position = 0;
    while ((position = value.find('"', position)) != std::string::npos) {
        value.insert(position, 1, '\\');
        position += 2;
    }

    return value;
}

}  // namespace

class CortexConfigManagerTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_AICortexConfig_"};

    [[nodiscard]] fs::path CreateModelDirectory() const {
        return tempDir.CreateDir(L"models");
    }

    [[nodiscard]] fs::path WriteConfigFile(const std::wstring& fileName,
                                           const std::string& jsonContent) const {
        const fs::path path = tempDir.File(fileName);
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        stream << jsonContent;
        stream.close();
        return path;
    }

    [[nodiscard]] nlohmann::json ReadJsonFile(const fs::path& path) const {
        std::ifstream stream(path, std::ios::binary);
        if (!stream) {
            throw std::runtime_error("Failed to open JSON file");
        }
        return nlohmann::json::parse(stream);
    }
};

TEST_F(CortexConfigManagerTest, InstanceReturnsStableSingletonReference) {
    auto& first = CortexConfigManager::Instance();
    auto& second = CortexConfigManager::Instance();

    EXPECT_EQ(&first, &second);
}

TEST_F(CortexConfigManagerTest, LoadConfigRejectsEmptyAndTraversalPaths) {
    auto& manager = CortexConfigManager::Instance();

    EXPECT_FALSE(manager.LoadConfig({}));
    EXPECT_FALSE(manager.LoadConfig(fs::path{L"..\\malicious\\config.json"}));
}

TEST_F(CortexConfigManagerTest, LoadConfigReturnsFalseForMissingFile) {
    auto& manager = CortexConfigManager::Instance();

    EXPECT_FALSE(manager.LoadConfig(tempDir.File(L"missing.json")));
}

TEST_F(CortexConfigManagerTest, LoadConfigRejectsMalformedJson) {
    auto& manager = CortexConfigManager::Instance();
    const fs::path configPath = WriteConfigFile(L"malformed.json", R"json({"modelDirectory":)json");

    EXPECT_FALSE(manager.LoadConfig(configPath));
}

TEST_F(CortexConfigManagerTest, LoadConfigClampsThresholdsAndSanitizesTraversalModelDirectory) {
    auto& manager = CortexConfigManager::Instance();

    const fs::path configPath = WriteConfigFile(
        L"validated.json",
        R"json({
            "modelDirectory": "..\\untrusted\\models",
            "staticThreshold": -0.25,
            "behavioralThreshold": 1.25,
            "memoryThreshold": 0.70,
            "networkThreshold": 5.0,
            "emulationThreshold": -5.0,
            "ensembleThreshold": 0.75,
            "useGPU": false,
            "useAVX512": false,
            "maxBatchSize": 0,
            "inferenceTimeoutMs": 0
        })json");

    ASSERT_TRUE(manager.LoadConfig(configPath));
    const CortexConfig config = manager.GetConfig();

    EXPECT_TRUE(config.modelDirectory.empty());
    EXPECT_FLOAT_EQ(config.staticThreshold, 0.0f);
    EXPECT_FLOAT_EQ(config.behavioralThreshold, 1.0f);
    EXPECT_FLOAT_EQ(config.memoryThreshold, 0.70f);
    EXPECT_FLOAT_EQ(config.networkThreshold, 1.0f);
    EXPECT_FLOAT_EQ(config.emulationThreshold, 0.0f);
    EXPECT_FLOAT_EQ(config.ensembleThreshold, 0.75f);
    EXPECT_FALSE(config.useGPU);
    EXPECT_FALSE(config.useAVX512);
    EXPECT_EQ(config.maxBatchSize, 1u);
    EXPECT_EQ(config.inferenceTimeoutMs, CortexConstants::DEFAULT_INFERENCE_TIMEOUT_MS);
}

TEST_F(CortexConfigManagerTest, LoadConfigCapsOversizedBatchSizeAndTimeout) {
    auto& manager = CortexConfigManager::Instance();
    const fs::path modelDir = CreateModelDirectory();

    const std::string rawModelDirUtf8 = Utils::StringUtils::ToNarrow(modelDir.wstring());
    const std::string escapedModelDirUtf8 = EscapeJsonString(rawModelDirUtf8);
    const fs::path configPath = WriteConfigFile(
        L"limits.json",
        "{"
        "\"modelDirectory\":\"" + escapedModelDirUtf8 + "\","
        "\"maxBatchSize\":999999,"
        "\"inferenceTimeoutMs\":999999"
        "}");

    ASSERT_TRUE(manager.LoadConfig(configPath));
    const CortexConfig config = manager.GetConfig();

    EXPECT_EQ(config.modelDirectory, modelDir);
    EXPECT_EQ(config.maxBatchSize, CortexConstants::MAX_BATCH_SIZE);
    EXPECT_EQ(config.inferenceTimeoutMs, CortexConstants::MAX_INFERENCE_TIMEOUT_MS);
}

TEST_F(CortexConfigManagerTest, LoadConfigPreservesDefaultsForMissingFields) {
    auto& manager = CortexConfigManager::Instance();
    const fs::path modelDir = CreateModelDirectory();

    const std::string modelDirUtf8 =
        EscapeJsonString(Utils::StringUtils::ToNarrow(modelDir.wstring()));
    const fs::path configPath = WriteConfigFile(
        L"partial.json",
        "{"
        "\"modelDirectory\":\"" + modelDirUtf8 + "\","
        "\"useGPU\":false"
        "}");

    ASSERT_TRUE(manager.LoadConfig(configPath));
    const CortexConfig config = manager.GetConfig();

    EXPECT_EQ(config.modelDirectory, modelDir);
    EXPECT_FLOAT_EQ(config.staticThreshold, 0.5f);
    EXPECT_FLOAT_EQ(config.behavioralThreshold, 0.6f);
    EXPECT_FLOAT_EQ(config.memoryThreshold, 0.7f);
    EXPECT_FLOAT_EQ(config.networkThreshold, 0.8f);
    EXPECT_FLOAT_EQ(config.emulationThreshold, 0.6f);
    EXPECT_FLOAT_EQ(config.ensembleThreshold, 0.5f);
    EXPECT_FALSE(config.useGPU);
    EXPECT_TRUE(config.useAVX512);
    EXPECT_EQ(config.maxBatchSize, 32u);
    EXPECT_EQ(config.inferenceTimeoutMs, CortexConstants::DEFAULT_INFERENCE_TIMEOUT_MS);
}

TEST_F(CortexConfigManagerTest, FailedLoadConfigDoesNotMutatePreviouslyLoadedConfiguration) {
    auto& manager = CortexConfigManager::Instance();
    const fs::path modelDir = CreateModelDirectory();
    const std::string rawModelDirUtf8 = Utils::StringUtils::ToNarrow(modelDir.wstring());
    const std::string escapedModelDirUtf8 = EscapeJsonString(rawModelDirUtf8);

    const fs::path validPath = WriteConfigFile(
        L"baseline.json",
        "{"
        "\"modelDirectory\":\"" + escapedModelDirUtf8 + "\","
        "\"staticThreshold\":0.42,"
        "\"behavioralThreshold\":0.61,"
        "\"maxBatchSize\":16"
        "}");

    ASSERT_TRUE(manager.LoadConfig(validPath));
    const CortexConfig baseline = manager.GetConfig();

    const fs::path malformedPath = WriteConfigFile(
        L"broken.json",
        R"json({"modelDirectory":"unterminated")json");
    EXPECT_FALSE(manager.LoadConfig(malformedPath));

    const CortexConfig afterFailure = manager.GetConfig();
    EXPECT_EQ(afterFailure.modelDirectory, baseline.modelDirectory);
    EXPECT_FLOAT_EQ(afterFailure.staticThreshold, baseline.staticThreshold);
    EXPECT_FLOAT_EQ(afterFailure.behavioralThreshold, baseline.behavioralThreshold);
    EXPECT_EQ(afterFailure.maxBatchSize, baseline.maxBatchSize);
}

TEST_F(CortexConfigManagerTest, SaveConfigRejectsEmptyAndTraversalPaths) {
    auto& manager = CortexConfigManager::Instance();

    EXPECT_FALSE(manager.SaveConfig({}));
    EXPECT_FALSE(manager.SaveConfig(fs::path{L"..\\malicious\\output.json"}));
}

TEST_F(CortexConfigManagerTest, SaveConfigWritesRoundTrippableSnapshot) {
    auto& manager = CortexConfigManager::Instance();
    const fs::path modelDir = CreateModelDirectory();
    const std::string rawModelDirUtf8 = Utils::StringUtils::ToNarrow(modelDir.wstring());
    const std::string escapedModelDirUtf8 = EscapeJsonString(rawModelDirUtf8);

    const fs::path inputPath = WriteConfigFile(
        L"input.json",
        "{"
        "\"modelDirectory\":\"" + escapedModelDirUtf8 + "\","
        "\"staticThreshold\":0.33,"
        "\"behavioralThreshold\":0.66,"
        "\"memoryThreshold\":0.77,"
        "\"networkThreshold\":0.88,"
        "\"emulationThreshold\":0.44,"
        "\"ensembleThreshold\":0.55,"
        "\"useGPU\":false,"
        "\"useAVX512\":true,"
        "\"maxBatchSize\":64,"
        "\"inferenceTimeoutMs\":250"
        "}");

    ASSERT_TRUE(manager.LoadConfig(inputPath));

    const fs::path outputPath = tempDir.File(L"saved.json");
    ASSERT_TRUE(manager.SaveConfig(outputPath));
    ASSERT_TRUE(fs::exists(outputPath));

    const auto savedDoc = ReadJsonFile(outputPath);
    EXPECT_EQ(savedDoc.at("modelDirectory").get<std::string>(), rawModelDirUtf8);
    EXPECT_DOUBLE_EQ(savedDoc.at("staticThreshold").get<double>(), 0.33);
    EXPECT_DOUBLE_EQ(savedDoc.at("behavioralThreshold").get<double>(), 0.66);
    EXPECT_DOUBLE_EQ(savedDoc.at("memoryThreshold").get<double>(), 0.77);
    EXPECT_DOUBLE_EQ(savedDoc.at("networkThreshold").get<double>(), 0.88);
    EXPECT_DOUBLE_EQ(savedDoc.at("emulationThreshold").get<double>(), 0.44);
    EXPECT_DOUBLE_EQ(savedDoc.at("ensembleThreshold").get<double>(), 0.55);
    EXPECT_FALSE(savedDoc.at("useGPU").get<bool>());
    EXPECT_TRUE(savedDoc.at("useAVX512").get<bool>());
    EXPECT_EQ(savedDoc.at("maxBatchSize").get<uint32_t>(), 64u);
    EXPECT_EQ(savedDoc.at("inferenceTimeoutMs").get<uint32_t>(), 250u);
}

}  // namespace ShadowStrike::AI::Test
