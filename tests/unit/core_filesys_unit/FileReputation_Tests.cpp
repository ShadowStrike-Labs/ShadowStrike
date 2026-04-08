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
 * @file FileReputation_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::FileSystem::FileReputation.
 *
 * Coverage focus:
 * - configuration presets and statistics reset behavior
 * - initialization guards and empty-path handling
 * - whitelist/blacklist verdicts through the public query surface
 * - certificate trust bookkeeping and offline cloud submission behavior
 * - callback notification for unknown files and cache facade semantics
 */

#include "pch.h"

#include "CoreFileSystem_TestUtils.hpp"
#include "../../../src/Shared_modules/Core/FileSystem/FileReputation.hpp"
#include "../../../src/Shared_modules/Core/FileSystem/FileHasher.hpp"

#include <chrono>
#include <future>

namespace {

using namespace std::chrono_literals;
using namespace ShadowStrike::Core::FileSystem;
using namespace ShadowStrike::Tests::CoreFileSystem;
using ::testing::Contains;
using ::testing::HasSubstr;

class FileReputationTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();
        FileHasher::Instance().Shutdown();

        auto& reputation = FileReputation::Instance();
        reputation.ClearCache();
        reputation.Shutdown();
    }

    void TearDown() override {
        auto& reputation = FileReputation::Instance();

        for (const auto& hash : whitelisted_) {
            (void)reputation.RemoveFromWhitelist(hash);
        }
        for (const auto& hash : blacklisted_) {
            (void)reputation.RemoveFromBlacklist(hash);
        }

        reputation.ClearCache();
        reputation.Shutdown();
        FileHasher::Instance().Shutdown();
        TempDirectoryFixture::TearDown();
    }

    void RememberWhitelist(std::string hash) {
        whitelisted_.push_back(std::move(hash));
    }

    void RememberBlacklist(std::string hash) {
        blacklisted_.push_back(std::move(hash));
    }

    std::vector<std::string> whitelisted_;
    std::vector<std::string> blacklisted_;
};

TEST(FileReputationValueTests, ConfigPresetsAndStatisticsResetReflectOperationalModes) {
    const auto defaults = FileReputationConfig::CreateDefault();
    const auto offline = FileReputationConfig::CreateOffline();
    const auto highSecurity = FileReputationConfig::CreateHighSecurity();

    EXPECT_EQ(defaults.defaultMode, QueryMode::CloudEnabled);
    EXPECT_EQ(offline.defaultMode, QueryMode::LocalOnly);
    EXPECT_EQ(offline.cloudTimeout, 0u);
    EXPECT_FALSE(offline.submitUnknown);
    EXPECT_EQ(highSecurity.defaultMode, QueryMode::Comprehensive);
    EXPECT_EQ(highSecurity.cachePolicy, CachePolicy::CacheNegative);
    EXPECT_GT(highSecurity.malwareThreshold, defaults.malwareThreshold);

    FileReputationStatistics stats;
    stats.totalQueries.store(11, std::memory_order_relaxed);
    stats.cacheHits.store(5, std::memory_order_relaxed);
    stats.Reset();
    EXPECT_EQ(stats.totalQueries.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.cacheHits.load(std::memory_order_relaxed), 0u);
}

TEST_F(FileReputationTest, LocalListMutatorsRejectEmptyInputsAndMissingEntries) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    EXPECT_FALSE(reputation.AddToWhitelist("", "empty"));
    EXPECT_FALSE(reputation.RemoveFromWhitelist(MakeHexHash('9')));
    EXPECT_FALSE(reputation.AddToBlacklist("", "empty"));
    EXPECT_FALSE(reputation.RemoveFromBlacklist(MakeHexHash('8')));
}

TEST_F(FileReputationTest, CheckHashBeforeInitializeReturnsInvestigateResult) {
    auto& reputation = FileReputation::Instance();
    const auto result = reputation.CheckHash(MakeHexHash('a'));

    EXPECT_EQ(result.level, ReputationLevel::Unknown);
    EXPECT_EQ(result.recommendation, "Investigate");
    EXPECT_THAT(result.reasons, Contains(HasSubstr("not initialized")));
}

TEST_F(FileReputationTest, WhitelistLifecycleAndCheckHashReturnKnownSafe) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    const auto hash = MakeHexHash('b');
    ASSERT_TRUE(reputation.AddToWhitelist(hash, "unit-test-safe"));
    RememberWhitelist(hash);

    const auto result = reputation.CheckHash(hash, QueryMode::LocalOnly);

    EXPECT_TRUE(reputation.IsWhitelisted(hash));
    EXPECT_EQ(result.level, ReputationLevel::KnownSafe);
    EXPECT_EQ(result.primarySource, ReputationSource::LocalWhitelist);
    EXPECT_TRUE(result.isTrusted);
    EXPECT_TRUE(result.isWhitelisted);
    EXPECT_EQ(result.recommendation, "Allow");
    EXPECT_THAT(result.reasons, Contains(HasSubstr("whitelist")));
}

TEST_F(FileReputationTest, BlacklistLifecycleAndCheckHashReturnKnownMalware) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    const auto hash = MakeHexHash('c');
    ASSERT_TRUE(reputation.AddToBlacklist(hash, "UnitTest.Malware"));
    RememberBlacklist(hash);

    const auto result = reputation.CheckHash(hash, QueryMode::LocalOnly);

    EXPECT_TRUE(reputation.IsBlacklisted(hash));
    EXPECT_EQ(result.level, ReputationLevel::KnownMalware);
    EXPECT_EQ(result.primarySource, ReputationSource::LocalBlacklist);
    EXPECT_TRUE(result.isMalicious);
    EXPECT_TRUE(result.isBlacklisted);
    EXPECT_EQ(result.recommendation, "Block");
    EXPECT_EQ(result.threatName, "UnitTest.Malware");
}

TEST_F(FileReputationTest, CertificateTrustBookkeepingReturnsExpectedTrustLevels) {
    auto& reputation = FileReputation::Instance();

    const auto trustedThumbprint = MakeHexHash('d');
    const auto untrustedThumbprint = MakeHexHash('e');

    EXPECT_EQ(reputation.GetCertificateTrust(trustedThumbprint), TrustLevel::Unknown);
    ASSERT_TRUE(reputation.AddTrustedCertificate(trustedThumbprint, "enterprise allow"));
    ASSERT_TRUE(reputation.AddUntrustedCertificate(untrustedThumbprint, "enterprise block"));

    EXPECT_EQ(reputation.GetCertificateTrust(trustedThumbprint), TrustLevel::UserTrust);
    EXPECT_EQ(reputation.GetCertificateTrust(untrustedThumbprint), TrustLevel::Untrusted);
}

TEST_F(FileReputationTest, OfflineModeDisablesCloudSubmissionEndpoints) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    EXPECT_FALSE(reputation.IsCloudAvailable());
    EXPECT_FALSE(reputation.SubmitForAnalysis(L"C:\\does-not-matter.bin"));
    EXPECT_FALSE(reputation.SubmitMetadata(L"C:\\does-not-matter.bin"));
    EXPECT_FALSE(reputation.ReportFalsePositive(MakeHexHash('f'), "offline"));
    EXPECT_FALSE(reputation.ReportFalseNegative(MakeHexHash('g'), "offline"));
}

TEST_F(FileReputationTest, CheckFileRejectsEmptyPathBeforeHashing) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    const auto result = reputation.CheckFile(L"", QueryMode::LocalOnly);

    EXPECT_EQ(result.level, ReputationLevel::Unknown);
    EXPECT_EQ(result.recommendation, "Block");
    EXPECT_THAT(result.reasons, Contains("Invalid file path"));
}

TEST_F(FileReputationTest, CheckFileUsesHasherBackedWhitelistForRealOnDiskArtifacts) {
    auto& hasher = FileHasher::Instance();
    auto hasherConfig = FileHasherConfig::CreateMinimal();
    hasherConfig.enableCache = false;
    ASSERT_TRUE(hasher.Initialize(hasherConfig));

    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    const auto filePath = WriteText(L"known-safe.bin", "ShadowStrike whitelist candidate");
    const auto hash = hasher.ComputeSHA256(filePath.wstring());
    ASSERT_FALSE(hash.empty());
    ASSERT_TRUE(reputation.AddToWhitelist(hash, "real file whitelist"));
    RememberWhitelist(hash);

    const auto result = reputation.CheckFile(filePath.wstring(), QueryMode::LocalOnly);
    EXPECT_EQ(result.level, ReputationLevel::KnownSafe);
    EXPECT_EQ(result.primarySource, ReputationSource::LocalWhitelist);
    EXPECT_TRUE(result.isTrusted);
    EXPECT_TRUE(result.isWhitelisted);
    EXPECT_EQ(result.sha256, hash);
    EXPECT_FALSE(result.sha1.empty());
    EXPECT_FALSE(result.md5.empty());
}

TEST_F(FileReputationTest, UnknownHashTriggersRegisteredCallback) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    const auto hash = MakeHexHash('1');
    std::promise<std::pair<std::wstring, std::string>> callbackPromise;
    std::atomic<bool> callbackSeen{ false };

    const auto callbackId = reputation.RegisterUnknownFileCallback(
        [&](const std::wstring& filePath, const std::string& observedHash) {
            if (!callbackSeen.exchange(true)) {
                callbackPromise.set_value({ filePath, observedHash });
            }
        });

    ASSERT_NE(callbackId, 0u);

    const auto result = reputation.CheckHash(hash, QueryMode::LocalOnly);
    EXPECT_EQ(result.level, ReputationLevel::Unknown);

    auto future = callbackPromise.get_future();
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready);
    const auto [callbackPath, callbackHash] = future.get();
    EXPECT_TRUE(callbackPath.empty());
    EXPECT_EQ(callbackHash, hash);
    EXPECT_TRUE(reputation.UnregisterCallback(callbackId));
    EXPECT_FALSE(reputation.UnregisterCallback(callbackId));
}

TEST_F(FileReputationTest, CacheFacadeAndStatisticsResetExposeStableBehavior) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    const auto hash = MakeHexHash('2');
    ASSERT_TRUE(reputation.AddToWhitelist(hash, "cache reset"));
    RememberWhitelist(hash);

    (void)reputation.CheckHash(hash, QueryMode::LocalOnly);
    const auto& statsBeforeReset = reputation.GetStatistics();
    EXPECT_GE(statsBeforeReset.totalQueries.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(statsBeforeReset.localHits.load(std::memory_order_relaxed), 1u);

    reputation.ResetStatistics();
    const auto& statsAfterReset = reputation.GetStatistics();
    EXPECT_EQ(statsAfterReset.totalQueries.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(statsAfterReset.localHits.load(std::memory_order_relaxed), 0u);

    EXPECT_EQ(reputation.GetCacheSize(), 0u);
    EXPECT_EQ(reputation.PreloadCache(WriteText(L"cache.rep", "cache").wstring()), 0u);
    EXPECT_TRUE(reputation.SaveCache(MakePath(L"cache-save.rep").wstring()));
}

TEST_F(FileReputationTest, BatchCheckPreservesInputCardinalityForInvalidPaths) {
    auto& reputation = FileReputation::Instance();
    ASSERT_TRUE(reputation.Initialize(FileReputationConfig::CreateOffline()));

    const std::vector<std::wstring> paths{
        L"",
        MakePath(L"missing.bin").wstring()
    };

    const auto results = reputation.CheckFiles(paths);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0].recommendation, "Block");
    EXPECT_THAT(results[0].reasons, Contains("Invalid file path"));
    EXPECT_EQ(results[1].recommendation, "Block");
    EXPECT_THAT(results[1].reasons, Contains(HasSubstr("hash computation failed")));
}

}  // namespace
