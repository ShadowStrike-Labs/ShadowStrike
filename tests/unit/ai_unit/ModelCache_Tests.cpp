/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Comprehensive unit coverage for PhantomCortex model cache and integrity
 * management. These tests stay fully local: they exercise path validation,
 * atomic swap, manifest persistence, rollback, and tamper detection without
 * requiring any network or ONNX runtime dependency.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "../../../src/PhantomCore/AI/ModelCache.hpp"
#include "../../../src/PhantomCore/Utils/HashUtils.hpp"
#include "../../../src/PhantomCore/Utils/StringUtils.hpp"
#include "../../../include/nlohmann/json.hpp"
#include "AI_TestUtils.hpp"

namespace fs = std::filesystem;

namespace ShadowStrike::AI::Test {

namespace {

constexpr std::array<const wchar_t*, CortexConstants::MODEL_COUNT> kSlotNames = {
    L"static",
    L"behavioral",
    L"memory",
    L"network",
    L"emulation"
};

std::wstring ComputeSha256Hex(const fs::path& filePath) {
    std::vector<uint8_t> digest;
    Utils::HashUtils::Error error{};
    if (!Utils::HashUtils::ComputeFile(Utils::HashUtils::Algorithm::SHA256,
                                       filePath.wstring(),
                                       digest,
                                       &error)) {
        return {};
    }

    return Utils::StringUtils::ToWide(Utils::HashUtils::ToHexLower(digest));
}

}  // namespace

class ModelCacheTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_AIModelCache_"};

    [[nodiscard]] fs::path CacheRoot() const {
        return tempDir.Path() / L"cache";
    }

    [[nodiscard]] fs::path CreateModelFile(const std::wstring& name,
                                           std::initializer_list<uint8_t> bytes) const {
        const fs::path path = tempDir.File(name);
        const std::vector<uint8_t> data(bytes);
        WriteBinaryFile(path, data);
        return path;
    }

    [[nodiscard]] fs::path SlotDirectory(const size_t index) const {
        return CacheRoot() / kSlotNames[index];
    }

    [[nodiscard]] nlohmann::json ReadJsonFile(const fs::path& path) const {
        std::ifstream stream(path, std::ios::binary);
        if (!stream) {
            throw std::runtime_error("Failed to open JSON file");
        }
        return nlohmann::json::parse(stream);
    }

    void InitializeCache() {
        ASSERT_TRUE(ModelCache::Instance().Initialize(CacheRoot()));
    }
};

TEST_F(ModelCacheTest, InstanceReturnsStableSingletonReference) {
    auto& first = ModelCache::Instance();
    auto& second = ModelCache::Instance();

    EXPECT_EQ(&first, &second);
}

TEST_F(ModelCacheTest, InitializeRejectsEmptyAndTraversalPaths) {
    auto& cache = ModelCache::Instance();

    EXPECT_FALSE(cache.Initialize({}));
    EXPECT_FALSE(cache.Initialize(fs::path{L"..\\cache"}));
}

TEST_F(ModelCacheTest, InitializeCreatesSlotDirectoriesAndStartsEmpty) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    for (size_t i = 0; i < kSlotNames.size(); ++i) {
        EXPECT_TRUE(fs::exists(SlotDirectory(i)));
        EXPECT_TRUE(fs::is_directory(SlotDirectory(i)));
        EXPECT_FALSE(cache.GetModelPath(static_cast<CortexModelType>(i)).has_value());
        EXPECT_FALSE(cache.VerifyIntegrity(static_cast<CortexModelType>(i)));
    }
}

TEST_F(ModelCacheTest, SwapModelRejectsTraversalAndMissingFiles) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    EXPECT_FALSE(cache.SwapModel(CortexModelType::Static, fs::path{L"..\\outside\\model.onnx"}));
    EXPECT_FALSE(cache.SwapModel(CortexModelType::Static, tempDir.File(L"missing.onnx")));
}

TEST_F(ModelCacheTest, InvalidModelTypesAreRejectedByPublicStatefulApis) {
    InitializeCache();
    auto& cache = ModelCache::Instance();
    const auto invalidType = static_cast<CortexModelType>(255);

    EXPECT_FALSE(cache.GetModelPath(invalidType).has_value());
    EXPECT_FALSE(cache.VerifyIntegrity(invalidType));
    EXPECT_FALSE(cache.Rollback(invalidType));
    EXPECT_FALSE(cache.DownloadModel(invalidType, L"https://example.test/model.onnx", L"deadbeef"));
}

TEST_F(ModelCacheTest, SwapModelActivatesModelWritesManifestAndPassesIntegrityVerification) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    const fs::path stagedModel = CreateModelFile(L"static_v1.onnx", {0x01, 0x02, 0x03, 0x04, 0x05});
    const std::wstring expectedHash = ComputeSha256Hex(stagedModel);
    ASSERT_FALSE(expectedHash.empty());

    ASSERT_TRUE(cache.SwapModel(CortexModelType::Static, stagedModel));

    const auto activePath = cache.GetModelPath(CortexModelType::Static);
    ASSERT_TRUE(activePath.has_value());
    EXPECT_EQ(activePath->filename(), fs::path{L"current.onnx"});
    EXPECT_TRUE(cache.VerifyIntegrity(CortexModelType::Static));

    const fs::path manifestPath = SlotDirectory(0) / L"manifest.json";
    const auto manifestDoc = ReadJsonFile(manifestPath);
    EXPECT_EQ(Utils::StringUtils::ToWide(manifestDoc.at("sha256").get<std::string>()), expectedHash);
    EXPECT_EQ(manifestDoc.at("version").at("patch").get<uint32_t>(), 1u);
}

TEST_F(ModelCacheTest, SwapModelTwiceThenRollbackRestoresPreviousBytes) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    const fs::path v1 = CreateModelFile(L"behavioral_v1.onnx", {0x10, 0x11, 0x12, 0x13});
    const fs::path v2 = CreateModelFile(L"behavioral_v2.onnx", {0x90, 0x91, 0x92, 0x93, 0x94});

    ASSERT_TRUE(cache.SwapModel(CortexModelType::Behavioral, v1));
    ASSERT_TRUE(cache.SwapModel(CortexModelType::Behavioral, v2));

    auto activePath = cache.GetModelPath(CortexModelType::Behavioral);
    ASSERT_TRUE(activePath.has_value());
    EXPECT_EQ(ReadBinaryFile(*activePath), ReadBinaryFile(v2));

    ASSERT_TRUE(cache.Rollback(CortexModelType::Behavioral));
    activePath = cache.GetModelPath(CortexModelType::Behavioral);
    ASSERT_TRUE(activePath.has_value());
    EXPECT_EQ(ReadBinaryFile(*activePath), ReadBinaryFile(v1));
    EXPECT_TRUE(cache.VerifyIntegrity(CortexModelType::Behavioral));
}

TEST_F(ModelCacheTest, VerifyIntegrityDetectsPostSwapTampering) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    const fs::path model = CreateModelFile(L"memory_v1.onnx", {0xA0, 0xA1, 0xA2, 0xA3});
    ASSERT_TRUE(cache.SwapModel(CortexModelType::Memory, model));

    const auto activePath = cache.GetModelPath(CortexModelType::Memory);
    ASSERT_TRUE(activePath.has_value());

    std::ofstream stream(*activePath, std::ios::binary | std::ios::app);
    ASSERT_TRUE(stream.good());
    stream.put(static_cast<char>(0x7F));
    stream.close();

    EXPECT_FALSE(cache.VerifyIntegrity(CortexModelType::Memory));
}

TEST_F(ModelCacheTest, RollbackReturnsFalseWhenNoPreviousVersionExists) {
    InitializeCache();

    EXPECT_FALSE(ModelCache::Instance().Rollback(CortexModelType::Network));
}

TEST_F(ModelCacheTest, InitializeReprobesPreviouslyActivatedModelState) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    const fs::path model = CreateModelFile(L"emulation_v1.onnx", {0x31, 0x32, 0x33, 0x34});
    ASSERT_TRUE(cache.SwapModel(CortexModelType::Emulation, model));
    ASSERT_TRUE(cache.VerifyIntegrity(CortexModelType::Emulation));

    ASSERT_TRUE(cache.Initialize(CacheRoot()));

    const auto activePath = cache.GetModelPath(CortexModelType::Emulation);
    ASSERT_TRUE(activePath.has_value());
    EXPECT_EQ(activePath->filename(), fs::path{L"current.onnx"});
    EXPECT_EQ(ReadBinaryFile(*activePath), ReadBinaryFile(model));
    EXPECT_TRUE(cache.VerifyIntegrity(CortexModelType::Emulation));
}

TEST_F(ModelCacheTest, DownloadModelRejectsInvalidInputsBeforeAnyNetworkActivity) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    EXPECT_FALSE(cache.DownloadModel(CortexModelType::Static, L"", L"deadbeef"));
    EXPECT_FALSE(cache.DownloadModel(CortexModelType::Static, L"https://example.test/model.onnx", L""));
    EXPECT_FALSE(cache.DownloadModel(CortexModelType::Static, L"http://example.test/model.onnx", L"deadbeef"));
}

TEST_F(ModelCacheTest, CheckForUpdatesRejectsInvalidManifestUrlsBeforeAnyNetworkActivity) {
    InitializeCache();
    auto& cache = ModelCache::Instance();

    EXPECT_FALSE(cache.CheckForUpdates(L""));
    EXPECT_FALSE(cache.CheckForUpdates(L"http://example.test/manifest.json"));
}

}  // namespace ShadowStrike::AI::Test
