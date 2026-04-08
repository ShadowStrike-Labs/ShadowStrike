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
 * @file RansomwareDecryptor_ValueContracts_Tests.cpp
 * @brief Value-contract coverage for Ransomware::RansomwareDecryptor.
 */

#include "pch.h"

#include "../../../src/Shared_modules/RansomwareProtection/RansomwareDecryptor.hpp"

#include <algorithm>

namespace {

using namespace ShadowStrike::Ransomware;
using ::testing::HasSubstr;

TEST(RansomwareDecryptorValueContractTests, ConfigCompatibilityRulesHelpersAndVersionRemainStable) {
    RansomwareDecryptorConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidConcurrent = config;
    invalidConcurrent.maxConcurrent = 0;
    EXPECT_FALSE(invalidConcurrent.IsValid());

    auto invalidTimeout = config;
    invalidTimeout.fileTimeoutMs = 0;
    EXPECT_FALSE(invalidTimeout.IsValid());

    DecryptorStatistics stats;
    stats.filesAnalyzed.store(1, std::memory_order_relaxed);
    stats.filesDecrypted.store(2, std::memory_order_relaxed);
    stats.filesFailed.store(3, std::memory_order_relaxed);
    stats.bytesDecrypted.store(4, std::memory_order_relaxed);
    stats.keysLoaded.store(5, std::memory_order_relaxed);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"keysLoaded\":5"));
    stats.Reset();

    EXPECT_EQ(stats.filesAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.filesDecrypted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.filesFailed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesDecrypted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.keysLoaded.load(std::memory_order_relaxed), 0u);

    EncryptedFileInfo file;
    file.filePath = L"C:\\Victim\\ledger.locky";
    file.family = RansomwareFamily::Locky;
    file.algorithm = EncryptionAlgorithm::AES256CTR;
    file.victimId = "victim-1";

    DecryptionKey key;
    key.keyId = "locky-key-1";
    key.keyType = KeyType::MasterKey;
    key.source = KeySource::Research;
    key.family = RansomwareFamily::Locky;
    key.algorithm = EncryptionAlgorithm::AES256CTR;
    key.victimIds = { "victim-1" };
    key.keyData = { 0xAA, 0xBB, 0xCC };
    key.iv = { 0x01, 0x02, 0x03 };
    key.rsaPrivateKey = "PRIVATE-KEY-MATERIAL";
    key.notes = "unit-test";

    EXPECT_TRUE(key.IsValidFor(file));

    key.victimIds = { "victim-2" };
    key.isMasterKey = false;
    EXPECT_FALSE(key.IsValidFor(file));

    key.isMasterKey = true;
    EXPECT_TRUE(key.IsValidFor(file));

    const auto keyJson = key.ToJson();
    EXPECT_THAT(keyJson, HasSubstr("\"keyId\":\"locky-key-1\""));
    EXPECT_EQ(keyJson.find("PRIVATE-KEY-MATERIAL"), std::string::npos);

    BatchDecryptionResult batch;
    batch.batchId = "batch-7";
    batch.totalFiles = 4;
    batch.filesDecrypted = 3;
    batch.filesFailed = 1;
    batch.bytesProcessed = 4096;
    EXPECT_DOUBLE_EQ(batch.GetSuccessRate(), 0.75);
    EXPECT_THAT(batch.ToJson(), HasSubstr("\"successRate\":0.75"));

    EXPECT_EQ(RansomwareDecryptor::GetFamilyName(RansomwareFamily::Ryuk), "Ryuk");
    EXPECT_EQ(GetDecryptionStatusName(DecryptionStatus::AlreadyDecrypted), "AlreadyDecrypted");
    EXPECT_EQ(GetKeyTypeName(KeyType::OfflineKey), "OfflineKey");
    EXPECT_EQ(GetAlgorithmName(EncryptionAlgorithm::ChaCha20), "ChaCha20");
    EXPECT_EQ(GetKeySourceName(KeySource::LawEnforcement), "LawEnforcement");

    const auto lockyExtensions = GetFamilyExtensions(RansomwareFamily::Locky);
    EXPECT_FALSE(lockyExtensions.empty());
    EXPECT_NE(std::find(lockyExtensions.begin(), lockyExtensions.end(), L".locky"),
              lockyExtensions.end());

    const auto wannaCryNotes = GetFamilyRansomNotes(RansomwareFamily::WannaCry);
    EXPECT_NE(std::find(wannaCryNotes.begin(), wannaCryNotes.end(), L"@WanaDecryptor@.txt"),
              wannaCryNotes.end());

    EXPECT_EQ(RansomwareDecryptor::GetVersionString(), "3.1.0");
}

}  // namespace
