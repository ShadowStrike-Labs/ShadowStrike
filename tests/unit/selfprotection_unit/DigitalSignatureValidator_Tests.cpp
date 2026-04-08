#include "../../../src/pch.h"
#include <nlohmann/json.hpp>
#include "../../../src/Shared_modules/SelfProtection/DigitalSignatureValidator.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(DigitalSignatureValidatorTests, SignerValidityAndFormattingReflectTrustMetadata) {
    const auto now = std::chrono::system_clock::now();

    SignerInfo signer{};
    signer.signerName = L"ShadowStrike Labs";
    signer.organization = L"ShadowStrike";
    signer.issuerName = L"ShadowStrike Root";
    signer.validFrom = now - std::chrono::hours{1};
    signer.validTo = now + std::chrono::hours{24};
    signer.trustLevel = SignerTrustLevel::EVValidated;
    signer.isEV = true;

    EXPECT_TRUE(signer.IsValid());

    const std::wstring description = signer.ToString();
    EXPECT_THAT(description, ::testing::HasSubstr(L"Signer: ShadowStrike Labs"));
    EXPECT_THAT(description, ::testing::HasSubstr(L"(ShadowStrike)"));
    EXPECT_THAT(description, ::testing::HasSubstr(L"Trust: EVValidated"));
    EXPECT_THAT(description, ::testing::HasSubstr(L"[EV]"));
}

TEST(DigitalSignatureValidatorTests, SignatureInfoTracksNewestTimestampAndSerializesFlags) {
    const auto now = std::chrono::system_clock::now();

    TimestampInfo validTimestamp{};
    validTimestamp.timestamp = now - std::chrono::hours{2};
    validTimestamp.tsaName = L"Trusted TSA";
    validTimestamp.status = TimestampStatus::Valid;

    TimestampInfo newestTimestamp{};
    newestTimestamp.timestamp = now;
    newestTimestamp.tsaName = L"Newest TSA";
    newestTimestamp.status = TimestampStatus::Invalid;

    SignatureInfo info{};
    info.result = SignatureValidationResult::Valid;
    info.isValid = true;
    info.type = SignatureType::Embedded;
    info.signer.signerName = L"ShadowStrike Labs";
    info.signer.issuerName = L"ShadowStrike Root";
    info.isMicrosoftSigned = true;
    info.isEV = true;
    info.isWHQL = false;
    info.isDualSigned = true;
    info.timestamps = {validTimestamp, newestTimestamp};

    EXPECT_TRUE(info.HasValidTimestamp());
    ASSERT_TRUE(info.GetNewestTimestamp().has_value());
    EXPECT_EQ(info.GetNewestTimestamp()->tsaName, L"Newest TSA");

    const std::string summary = info.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("Result: Valid"));
    EXPECT_THAT(summary, ::testing::HasSubstr("Type: Embedded"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[VALID]"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[MICROSOFT]"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[EV]"));

    const json payload = ParseJson(info.ToJson());
    EXPECT_EQ(payload.at("result").get<std::string>(), "Valid");
    EXPECT_TRUE(payload.at("isValid").get<bool>());
    EXPECT_EQ(payload.at("type").get<std::string>(), "Embedded");
    EXPECT_EQ(payload.at("signerName").get<std::string>(), "ShadowStrike Labs");
    EXPECT_TRUE(payload.at("isMicrosoftSigned").get<bool>());
    EXPECT_TRUE(payload.at("isEV").get<bool>());
    EXPECT_TRUE(payload.at("isDualSigned").get<bool>());
    EXPECT_TRUE(payload.at("hasTimestamp").get<bool>());

    SignatureInfo invalidOnly{};
    invalidOnly.timestamps = {newestTimestamp};

    EXPECT_FALSE(invalidOnly.HasValidTimestamp());
    ASSERT_TRUE(invalidOnly.GetNewestTimestamp().has_value());
    EXPECT_EQ(invalidOnly.GetNewestTimestamp()->tsaName, L"Newest TSA");

    const json invalidOnlyPayload = ParseJson(invalidOnly.ToJson());
    EXPECT_FALSE(invalidOnlyPayload.at("hasTimestamp").get<bool>());
}

TEST(DigitalSignatureValidatorTests, ConfigurationStatisticsAndHelperNamesStayStable) {
    SignatureValidatorConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.cacheDurationSecs = 0;
    EXPECT_FALSE(config.IsValid());

    config = SignatureValidatorConfiguration{};
    config.trustedPublishers.resize(SignatureConstants::MAX_TRUSTED_PUBLISHERS + 1);
    EXPECT_FALSE(config.IsValid());

    SignatureValidatorStatistics stats{};
    stats.totalValidations = 4;
    stats.validSignatures = 3;
    stats.invalidSignatures = 1;
    stats.blockedSigners = 2;

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalValidations").get<int>(), 4);
    EXPECT_EQ(payload.at("validSignatures").get<int>(), 3);
    EXPECT_EQ(payload.at("blockedSigners").get<int>(), 2);
    EXPECT_EQ(payload.at("anomalyDetections").get<int>(), 0);

    EXPECT_EQ(GetSignatureResultName(SignatureValidationResult::WeakAlgorithm), "WeakAlgorithm");
    EXPECT_EQ(GetSignatureTypeName(SignatureType::Catalog), "Catalog");
    EXPECT_EQ(GetHashAlgorithmName(SignatureHashAlgorithm::SHA512), "SHA512");
    EXPECT_EQ(GetSignerTrustLevelName(SignerTrustLevel::HighlyTrusted), "HighlyTrusted");
    EXPECT_EQ(GetTimestampStatusName(TimestampStatus::UntrustedTSA), "UntrustedTSA");
    EXPECT_EQ(GetSignedFileTypeName(SignedFileType::PEDriver), "PEDriver");
}

}  // namespace
