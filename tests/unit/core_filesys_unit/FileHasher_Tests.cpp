/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file FileHasher_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::FileSystem::FileHasher.
 *
 * Coverage focus:
 * - hash algorithm flag composition and configuration presets
 * - deterministic cryptographic hashing for memory buffers and files
 * - cache population, statistics tracking, and reset semantics
 * - serialization helpers and hex format validation
 * - async callback delivery and self-test behavior
 */

#include "pch.h"

#include "CoreFileSystem_TestUtils.hpp"
#include "../../../src/Shared_modules/Core/FileSystem/FileHasher.hpp"

#include <chrono>
#include <future>
#include <thread>

namespace {

using namespace std::chrono_literals;
using namespace ShadowStrike::Core::FileSystem;
using namespace ShadowStrike::Tests::CoreFileSystem;
using ::testing::HasSubstr;

class FileHasherTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();

        auto& hasher = FileHasher::Instance();
        hasher.Shutdown();

        FileHasherConfig config = FileHasherConfig::CreateDefault();
        config.workerThreads = 2;
        config.enableCache = true;
        ASSERT_TRUE(hasher.Initialize(config));
    }

    void TearDown() override {
        auto& hasher = FileHasher::Instance();
        hasher.ClearCache();
        hasher.Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(FileHasherValueTests, HashAlgorithmBitmaskOperationsHonorCompositeFlags) {
    const auto crypto = HashAlgorithm::MD5 | HashAlgorithm::SHA256;
    EXPECT_TRUE(HasFlag(crypto, HashAlgorithm::MD5));
    EXPECT_TRUE(HasFlag(crypto, HashAlgorithm::SHA256));
    EXPECT_FALSE(HasFlag(crypto, HashAlgorithm::SHA1));

    const auto modern = HashAlgorithm::Modern;
    EXPECT_TRUE(HasFlag(modern, HashAlgorithm::SHA256));
    EXPECT_TRUE(HasFlag(modern, HashAlgorithm::SHA3_256));
    EXPECT_TRUE(HasFlag(modern, HashAlgorithm::FUZZY));
}

TEST(FileHasherValueTests, ConfigPresetsReflectExpectedTradeoffs) {
    const auto defaults = FileHasherConfig::CreateDefault();
    const auto fast = FileHasherConfig::CreateHighPerformance();
    const auto comprehensive = FileHasherConfig::CreateComprehensive();
    const auto minimal = FileHasherConfig::CreateMinimal();

    EXPECT_TRUE(HasFlag(defaults.defaultAlgorithms, HashAlgorithm::SHA256));
    EXPECT_GT(fast.bufferSize, defaults.bufferSize);
    EXPECT_GT(fast.maxCacheSize, defaults.maxCacheSize);
    EXPECT_TRUE(HasFlag(comprehensive.defaultAlgorithms, HashAlgorithm::AUTHENTIHASH));
    EXPECT_TRUE(comprehensive.computeFuzzyHashes);
    EXPECT_FALSE(minimal.enableCache);
    EXPECT_FALSE(minimal.computeFuzzyHashes);
    EXPECT_EQ(minimal.workerThreads, 1u);
}

TEST(FileHasherValueTests, FileHashesAndComparisonsSerializeMeaningfulFields) {
    FileHashes hashes;
    hashes.filePath = L"C:\\sample.bin";
    hashes.fileSize = 3;
    hashes.sha256Hex = "abc123";
    hashes.hasSHA256 = true;

    EXPECT_TRUE(hashes.IsValid());
    EXPECT_THAT(hashes.ToJson(), HasSubstr("\"sha256\": \"abc123\""));

    HashComparison comparison;
    comparison.sha256Match = true;
    comparison.fuzzySimilarity = 60.0;
    comparison.tlshDistance = 50;

    EXPECT_TRUE(comparison.IsMatch());
    EXPECT_TRUE(comparison.IsSimilar());
    EXPECT_THAT(comparison.ToJson(), HasSubstr("\"isMatch\": true"));
}

TEST(FileHasherValueTests, EmptyAndBoundaryHelpersReflectExactComparisonSemantics) {
    FileHashes emptyHashes;
    EXPECT_FALSE(emptyHashes.IsValid());

    HashComparison fuzzyBoundary;
    fuzzyBoundary.fuzzySimilarity = 50.0;
    EXPECT_TRUE(fuzzyBoundary.IsSimilar());

    HashComparison tlshBoundary;
    tlshBoundary.tlshDistance = 100;
    EXPECT_TRUE(tlshBoundary.IsSimilar());

    HashComparison belowBoundary;
    belowBoundary.fuzzySimilarity = 49.99;
    belowBoundary.tlshDistance = 101;
    EXPECT_FALSE(belowBoundary.IsSimilar());
}

TEST_F(FileHasherTest, ComputeBufferHashesMatchesKnownVectors) {
    auto& hasher = FileHasher::Instance();
    const auto input = Bytes("abc");

    EXPECT_EQ(hasher.ComputeMD5(input), "900150983cd24fb0d6963f7d28e17f72");
    EXPECT_EQ(hasher.ComputeSHA256(input), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(FileHasherTest, ComputeAllBufferPopulatesMetadataValidityAndRequestedAlgorithms) {
    auto& hasher = FileHasher::Instance();
    const auto payload = Bytes("ShadowStrike-buffer-payload");

    const auto hashes = hasher.ComputeAll(payload, HashAlgorithm::MD5 | HashAlgorithm::SHA256);

    EXPECT_EQ(hashes.filePath, L"<memory buffer>");
    EXPECT_EQ(hashes.fileSize, payload.size());
    EXPECT_TRUE(hashes.hasMD5);
    EXPECT_TRUE(hashes.hasSHA256);
    EXPECT_FALSE(hashes.hasSHA1);
    EXPECT_TRUE(hashes.IsValid());
    EXPECT_FALSE(hashes.md5Hex.empty());
    EXPECT_FALSE(hashes.sha256Hex.empty());
}

TEST_F(FileHasherTest, ComputeFileHashesPopulateCacheAndStatisticsForOnDiskFile) {
    auto& hasher = FileHasher::Instance();
    const auto filePath = WriteText(L"payload.bin", "ShadowStrike file hashing test");

    const auto hashes = hasher.ComputeAll(filePath.wstring(), HashAlgorithm::MD5 | HashAlgorithm::SHA256);
    const auto cached = hasher.GetCached(filePath.wstring());
    const auto stats = hasher.GetStatistics();

    ASSERT_TRUE(hashes.hasMD5);
    ASSERT_TRUE(hashes.hasSHA256);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->sha256Hex, hashes.sha256Hex);
    EXPECT_EQ(hasher.GetCacheSize(), 1u);
    EXPECT_GE(stats.filesHashed, 1u);
    EXPECT_GE(stats.bytesProcessed, hashes.fileSize);
    EXPECT_GE(stats.cacheMisses, 1u);
}

TEST_F(FileHasherTest, CachedEntriesAreInvalidatedWhenFileContentsChange) {
    auto& hasher = FileHasher::Instance();
    const auto filePath = WriteText(L"mutable.bin", "original payload");

    const auto firstHashes = hasher.ComputeAll(filePath.wstring(), HashAlgorithm::SHA256);
    ASSERT_TRUE(firstHashes.hasSHA256);
    ASSERT_TRUE(hasher.GetCached(filePath.wstring()).has_value());

    std::this_thread::sleep_for(20ms);
    const auto rewrittenPath = WriteText(L"mutable.bin", "updated payload");
    EXPECT_EQ(rewrittenPath, filePath);

    const auto secondHashes = hasher.ComputeAll(filePath.wstring(), HashAlgorithm::SHA256);
    ASSERT_TRUE(secondHashes.hasSHA256);
    EXPECT_NE(firstHashes.sha256Hex, secondHashes.sha256Hex);
    ASSERT_TRUE(hasher.GetCached(filePath.wstring()).has_value());
    EXPECT_EQ(hasher.GetCached(filePath.wstring())->sha256Hex, secondHashes.sha256Hex);
}

TEST_F(FileHasherTest, HeaderHashUsesRequestedPrefixOnly) {
    auto& hasher = FileHasher::Instance();
    const auto filePath = WriteText(L"prefix.bin", "abcdef");
    const auto expectedPrefixHash = hasher.ComputeSHA256(Bytes("abc"));

    const auto headerHash = hasher.ComputeHeaderHash(filePath.wstring(), HashAlgorithm::SHA256, 3);

    EXPECT_EQ(headerHash, expectedPrefixHash);
}

TEST_F(FileHasherTest, HeaderHashHandlesZeroLengthAndMissingFilesSafely) {
    auto& hasher = FileHasher::Instance();
    const auto filePath = WriteText(L"empty-prefix.bin", "abcdef");

    EXPECT_TRUE(hasher.ComputeHeaderHash(filePath.wstring(), HashAlgorithm::SHA256, 0).empty());
    EXPECT_TRUE(hasher.ComputeHeaderHash(MakePath(L"missing.bin").wstring(), HashAlgorithm::SHA256, 16).empty());
}

TEST_F(FileHasherTest, HexUtilitiesRoundTripAndValidateHashFormats) {
    auto& hasher = FileHasher::Instance();
    const std::array<uint8_t, 3> raw{ 0x00, 0x0F, 0xA5 };

    EXPECT_EQ(hasher.ToHexString(raw, HashFormat::Hex), "000fa5");
    EXPECT_EQ(hasher.ToHexString(raw, HashFormat::HexUpper), "000FA5");
    EXPECT_EQ(hasher.ToHexString(raw, HashFormat::Base64), "000fa5");
    EXPECT_EQ(hasher.ToHexString(raw, HashFormat::Raw).size(), raw.size());

    const auto roundTrip = hasher.FromHexString("000FA5");
    ASSERT_EQ(roundTrip.size(), raw.size());
    EXPECT_EQ(roundTrip[0], 0x00);
    EXPECT_EQ(roundTrip[1], 0x0F);
    EXPECT_EQ(roundTrip[2], 0xA5);

    EXPECT_TRUE(hasher.ValidateHashFormat(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        HashAlgorithm::SHA256));
    EXPECT_TRUE(hasher.ValidateHashFormat(
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        HashAlgorithm::SHA256));
    EXPECT_FALSE(hasher.ValidateHashFormat("xyz", HashAlgorithm::SHA256));
    EXPECT_FALSE(hasher.ValidateHashFormat("1234", HashAlgorithm::FUZZY));
    EXPECT_TRUE(hasher.ToHexString(std::span<const uint8_t>{}, HashFormat::Hex).empty());
    EXPECT_TRUE(hasher.FromHexString("xyz").empty());
}

TEST_F(FileHasherTest, AsyncComputeInvokesDirectAndRegisteredCallbacks) {
    auto& hasher = FileHasher::Instance();
    const auto filePath = WriteText(L"async.bin", "async hashing payload");

    std::promise<void> directPromise;
    std::promise<void> registeredPromise;
    std::atomic<bool> directSeen{ false };
    std::atomic<bool> registeredSeen{ false };

    const auto callbackId = hasher.RegisterHashCallback(
        [&](const FileHashes& hashes) {
            EXPECT_TRUE(hashes.hasSHA256);
            if (!registeredSeen.exchange(true)) {
                registeredPromise.set_value();
            }
        });

    ASSERT_NE(callbackId, 0u);

    hasher.ComputeAllAsync(
        filePath.wstring(),
        [&](const FileHashes& hashes) {
            EXPECT_TRUE(hashes.hasSHA256);
            EXPECT_EQ(hashes.filePath, filePath.wstring());
            if (!directSeen.exchange(true)) {
                directPromise.set_value();
            }
        },
        HashAlgorithm::SHA256);

    EXPECT_EQ(directPromise.get_future().wait_for(5s), std::future_status::ready);
    EXPECT_EQ(registeredPromise.get_future().wait_for(5s), std::future_status::ready);
    EXPECT_TRUE(hasher.UnregisterHashCallback(callbackId));
}

TEST_F(FileHasherTest, FutureAsyncAndComparisonHelpersStayDeterministic) {
    auto& hasher = FileHasher::Instance();

    const auto leftPath = WriteText(L"compare-left.bin", "same payload");
    const auto rightPath = WriteText(L"compare-right.bin", "same payload");
    const auto differentPath = WriteText(L"compare-different.bin", "different payload");

    auto future = hasher.ComputeAllAsync(leftPath.wstring(), HashAlgorithm::SHA256);
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
    const auto leftHashes = future.get();
    const auto rightHashes = hasher.ComputeAll(rightPath.wstring(), HashAlgorithm::SHA256);
    const auto differentHashes = hasher.ComputeAll(differentPath.wstring(), HashAlgorithm::SHA256);

    ASSERT_TRUE(leftHashes.hasSHA256);
    ASSERT_TRUE(rightHashes.hasSHA256);
    ASSERT_TRUE(differentHashes.hasSHA256);

    const auto exactComparison = hasher.Compare(leftHashes, rightHashes);
    EXPECT_TRUE(exactComparison.sha256Match);
    EXPECT_TRUE(exactComparison.IsMatch());
    EXPECT_TRUE(hasher.MatchesAny(leftHashes, { differentHashes, rightHashes }));
    EXPECT_FALSE(hasher.MatchesAny(leftHashes, { differentHashes }));

    EXPECT_DOUBLE_EQ(hasher.CompareFuzzyHash("", ""), 0.0);
    EXPECT_EQ(hasher.ComputeTLSHDistance("", ""), UINT32_MAX);

    auto updatedConfig = hasher.GetConfig();
    updatedConfig.enableCache = false;
    updatedConfig.workerThreads = 1;
    hasher.UpdateConfig(updatedConfig);

    const auto reloadedConfig = hasher.GetConfig();
    EXPECT_FALSE(reloadedConfig.enableCache);
    EXPECT_EQ(reloadedConfig.workerThreads, 1u);
}

TEST_F(FileHasherTest, SelfTestPassesAndStatisticsResetClearsObservedWork) {
    auto& hasher = FileHasher::Instance();
    const auto filePath = WriteText(L"stats.bin", "statistics payload");

    EXPECT_FALSE(hasher.ComputeSHA256(filePath.wstring()).empty());
    auto stats = hasher.GetStatistics();
    EXPECT_GE(stats.filesHashed, 1u);
    EXPECT_TRUE(hasher.SelfTest());

    hasher.ResetStatistics();
    stats = hasher.GetStatistics();
    EXPECT_EQ(stats.filesHashed, 0u);
    EXPECT_EQ(stats.bytesProcessed, 0u);
    EXPECT_EQ(stats.cacheHits, 0u);
    EXPECT_EQ(stats.cacheMisses, 0u);
}

TEST_F(FileHasherTest, CacheAndDiagnosticHelpersExposeConsistentState) {
    auto& hasher = FileHasher::Instance();
    const auto filePath = WriteText(L"cache.bin", "cache helper payload");

    const auto hashes = hasher.ComputeAll(filePath.wstring(), HashAlgorithm::SHA256);
    ASSERT_TRUE(hashes.hasSHA256);
    ASSERT_TRUE(hasher.GetCached(filePath.wstring()).has_value());

    hasher.InvalidateCache(filePath.wstring());
    EXPECT_FALSE(hasher.GetCached(filePath.wstring()).has_value());

    (void)hasher.ComputeAll(filePath.wstring(), HashAlgorithm::SHA256);
    EXPECT_EQ(hasher.GetCacheSize(), 1u);
    hasher.ClearCache();
    EXPECT_EQ(hasher.GetCacheSize(), 0u);

    EXPECT_EQ(hasher.RegisterProgressCallback(nullptr), 0u);
    EXPECT_FALSE(hasher.UnregisterProgressCallback(999999u));

    const auto version = hasher.GetVersionInfo();
    EXPECT_FALSE(version.hasherVersion.empty());
    EXPECT_FALSE(version.fuzzyHasherVersion.empty());
    EXPECT_FALSE(version.tlshVersion.empty());

    const auto hardware = hasher.GetHardwareInfo();
    EXPECT_EQ(hardware.useHardwareAccel, hasher.HasHardwareAcceleration());

    for (const auto& feature : hasher.GetHardwareFeatures()) {
        EXPECT_TRUE(feature == "AES-NI" || feature == "SHA-NI");
    }
}

}  // namespace
