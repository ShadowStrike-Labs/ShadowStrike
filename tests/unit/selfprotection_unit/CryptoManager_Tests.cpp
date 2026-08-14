#include "../../../src/pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/CryptoManager.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(CryptoManagerTests, KeyMetadataExpirationAndSerializationExposeStableFields) {
    KeyMetadata metadata{};
    metadata.id = "kernel-session";
    metadata.type = KeyType::Symmetric;
    metadata.algorithm = SymmetricAlgorithm::AES_256_GCM;
    metadata.keySizeBits = 256;
    metadata.storage = KeyStorage::TPM;
    metadata.expiresAt = std::chrono::system_clock::now() - std::chrono::minutes{5};
    metadata.usageCount = 3;
    metadata.isExportable = true;
    metadata.description = "Primary kernel attestation key";

    EXPECT_TRUE(metadata.IsExpired());

    const json payload = ParseJson(metadata.ToJson());
    EXPECT_EQ(payload.at("id").get<std::string>(), "kernel-session");
    EXPECT_EQ(payload.at("type").get<int>(), static_cast<int>(KeyType::Symmetric));
    EXPECT_EQ(payload.at("keySizeBits").get<int>(), 256);
    EXPECT_EQ(payload.at("storage").get<int>(), static_cast<int>(KeyStorage::TPM));
    EXPECT_EQ(payload.at("usageCount").get<int>(), 3);
    EXPECT_TRUE(payload.at("isExportable").get<bool>());
    EXPECT_EQ(payload.at("description").get<std::string>(), "Primary kernel attestation key");
    EXPECT_FALSE(payload.contains("algorithm"));
    EXPECT_FALSE(payload.contains("createdAt"));
    EXPECT_FALSE(payload.contains("expiresAt"));
    EXPECT_FALSE(payload.contains("lastUsed"));
    EXPECT_FALSE(payload.contains("isExtractable"));
}

TEST(CryptoManagerTests, KdfFactoriesAndEncryptionOutputPreserveExpectedLayout) {
    const KDFParameters pbkdf2 = KDFParameters::PBKDF2(600000);
    EXPECT_EQ(pbkdf2.algorithm, KDFAlgorithm::PBKDF2_SHA256);
    EXPECT_EQ(pbkdf2.iterations, 600000U);
    EXPECT_EQ(pbkdf2.outputLength, 32U);

    const KDFParameters argon = KDFParameters::Argon2id(131072, 4);
    EXPECT_EQ(argon.algorithm, KDFAlgorithm::Argon2id);
    EXPECT_EQ(argon.memoryKB, 131072U);
    EXPECT_EQ(argon.iterations, 4U);
    EXPECT_EQ(argon.parallelism, 4U);

    const std::array<uint8_t, 3> info{0xAA, 0xBB, 0xCC};
    const KDFParameters hkdf = KDFParameters::HKDF(info);
    EXPECT_EQ(hkdf.algorithm, KDFAlgorithm::HKDF_SHA256);
    EXPECT_THAT(hkdf.info, ::testing::ElementsAre(0xAA, 0xBB, 0xCC));

    EncryptionResult result{};
    result.iv = {0x01, 0x02};
    result.ciphertext = {0x03, 0x04, 0x05};
    result.tag = {0x06, 0x07};

    EXPECT_THAT(result.GetCombinedOutput(),
                ::testing::ElementsAre(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07));
}

TEST(CryptoManagerTests, ConfigurationStatisticsAndSecureVectorBehavePredictably) {
    CryptoManagerConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.maxCachedKeys = 0;
    EXPECT_FALSE(config.IsValid());

    config = CryptoManagerConfiguration{};
    config.keyRotationIntervalSecs = 0;
    EXPECT_FALSE(config.IsValid());

    CryptoManagerStatistics stats{};
    stats.totalEncryptions = 5;
    stats.totalKeyDerivations = 2;
    stats.authenticationFailures = 1;
    stats.activeKeys = 4;
    stats.Reset();

    EXPECT_EQ(stats.totalEncryptions, 0ULL);
    EXPECT_EQ(stats.totalKeyDerivations, 0ULL);
    EXPECT_EQ(stats.authenticationFailures, 0ULL);
    EXPECT_EQ(stats.activeKeys, 0U);

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalEncryptions").get<int>(), 0);
    EXPECT_EQ(payload.at("totalKeyDerivations").get<int>(), 0);
    EXPECT_EQ(payload.at("activeKeys").get<int>(), 0);

    SecureVector secureBytes(6);
    ASSERT_EQ(secureBytes.size(), 6U);
    for (size_t i = 0; i < secureBytes.size(); ++i) {
        secureBytes.data()[i] = static_cast<uint8_t>(i + 1);
    }

    secureBytes.resize(3);
    EXPECT_EQ(secureBytes.size(), 3U);
    EXPECT_EQ(secureBytes.data()[0], 1U);
    EXPECT_EQ(secureBytes.data()[2], 3U);

    secureBytes.clear();
    EXPECT_TRUE(secureBytes.empty());
}

}  // namespace
