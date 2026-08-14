#include "../../../src/pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/CertificateValidator.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(CertificateValidatorTests, DistinguishedNamesAndValidityWindowsFormatPredictably) {
    DistinguishedName dn{};
    dn.commonName = "ShadowStrike Agent";
    dn.organization = "ShadowStrike Labs";
    dn.organizationalUnit = "EDR";
    dn.country = "US";
    dn.state = "Washington";
    dn.locality = "Seattle";
    dn.email = "security@shadowstrike.local";

    EXPECT_EQ(dn.ToString(),
              "CN=ShadowStrike Agent, O=ShadowStrike Labs, OU=EDR, C=US, ST=Washington, L=Seattle");

    const auto now = std::chrono::system_clock::now();

    ValidityPeriod current{};
    current.notBefore = now - std::chrono::hours{1};
    current.notAfter = now + std::chrono::hours{2};
    EXPECT_TRUE(current.IsValid());
    EXPECT_FALSE(current.IsExpired());
    EXPECT_FALSE(current.IsNotYetValid());
    EXPECT_GT(current.GetRemainingSeconds(), 0);

    ValidityPeriod future{};
    future.notBefore = now + std::chrono::hours{1};
    future.notAfter = now + std::chrono::hours{2};
    EXPECT_TRUE(future.IsNotYetValid());

    ValidityPeriod past{};
    past.notBefore = now - std::chrono::hours{4};
    past.notAfter = now - std::chrono::hours{1};
    EXPECT_TRUE(past.IsExpired());
    EXPECT_LT(past.GetRemainingSeconds(), 0);
}

TEST(CertificateValidatorTests, CertificateAndValidationDetailsSerializeUsefulMetadata) {
    const auto now = std::chrono::system_clock::now();

    CertificateInfo certificate{};
    certificate.version = 3;
    certificate.serialNumber = "01AABBCCDD";
    certificate.subject.commonName = "ShadowStrike Sensor";
    certificate.issuer.organization = "ShadowStrike Root CA";
    certificate.validity.notBefore = now - std::chrono::hours{24};
    certificate.validity.notAfter = now + std::chrono::hours{24};
    certificate.publicKey.type = CertificateKeyType::RSA;
    certificate.publicKey.keySizeBits = 4096;
    certificate.signatureAlgorithm = SignatureAlgorithm::SHA256_RSA;
    certificate.type = CertificateType::CodeSigning;
    certificate.sha256Fingerprint.fill(0xAB);
    certificate.sha1Thumbprint.fill(0xCD);

    const json certJson = ParseJson(certificate.ToJson());
    EXPECT_EQ(certJson.at("version").get<int>(), 3);
    EXPECT_EQ(certJson.at("serialNumber").get<std::string>(), "01AABBCCDD");
    EXPECT_EQ(certJson.at("subject").get<std::string>(), "CN=ShadowStrike Sensor");
    EXPECT_EQ(certJson.at("issuer").get<std::string>(), "O=ShadowStrike Root CA");
    EXPECT_EQ(certJson.at("keySizeBits").get<int>(), 4096);
    EXPECT_EQ(certJson.at("signatureAlgorithm").get<int>(),
              static_cast<int>(SignatureAlgorithm::SHA256_RSA));
    EXPECT_EQ(certJson.at("sha256Fingerprint").get<std::string>().size(), 64U);
    EXPECT_EQ(certJson.at("sha1Thumbprint").get<std::string>().size(), 40U);

    ValidationDetails details{};
    details.result = ValidationResult::Valid;
    details.errorMessage = "chain warning";
    details.errorCode = 7;
    details.chain = {certificate};
    details.trustLevel = TrustLevel::SystemRoot;
    details.revocationStatus = RevocationStatus::Good;
    details.isExtendedValidation = true;
    details.warnings = {"OCSP responder slow", "Stapled response unavailable"};

    const std::string summary = details.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("Validation Result: Valid"));
    EXPECT_THAT(summary, ::testing::HasSubstr("Trust Level: SystemRoot"));
    EXPECT_THAT(summary, ::testing::HasSubstr("Warnings: 2"));

    const json payload = ParseJson(details.ToJson());
    EXPECT_EQ(payload.at("resultName").get<std::string>(), "Valid");
    EXPECT_EQ(payload.at("errorCode").get<int>(), 7);
    EXPECT_EQ(payload.at("chainLength").get<int>(), 1);
    EXPECT_TRUE(payload.at("isExtendedValidation").get<bool>());
    ASSERT_EQ(payload.at("warnings").size(), 2U);
}

TEST(CertificateValidatorTests, ConfigurationStatisticsAndHelpersStayAligned) {
    CertificateValidatorConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.minRSAKeySize = 512;
    EXPECT_FALSE(config.IsValid());

    config = CertificateValidatorConfiguration{};
    config.minECCKeySize = 600;
    EXPECT_FALSE(config.IsValid());

    CertificateValidatorStatistics stats{};
    stats.totalValidations = 12;
    stats.validCertificates = 11;
    stats.invalidCertificates = 1;
    stats.revokedCertificates = 2;
    stats.avgValidationTimeUs = 5000;
    stats.Reset();

    EXPECT_EQ(stats.totalValidations, 0ULL);
    EXPECT_EQ(stats.validCertificates, 0ULL);
    EXPECT_EQ(stats.revokedCertificates, 0ULL);
    EXPECT_EQ(stats.avgValidationTimeUs, 0ULL);

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalValidations").get<int>(), 0);
    EXPECT_EQ(payload.at("chainBuildFailures").get<int>(), 0);
    EXPECT_GE(payload.at("uptimeMs").get<int64_t>(), 0);

    EXPECT_EQ(GetValidationResultName(ValidationResult::WeakAlgorithm), "WeakAlgorithm");
    EXPECT_EQ(GetCertificateTypeName(CertificateType::CodeSigning), "CodeSigning");
    EXPECT_EQ(GetKeyTypeName(CertificateKeyType::ECDSA), "ECDSA");
    EXPECT_EQ(GetSignatureAlgorithmName(SignatureAlgorithm::RSA_PSS), "RSA-PSS");
    EXPECT_EQ(GetRevocationStatusName(RevocationStatus::OCSPNotAvailable), "OCSPNotAvailable");
    EXPECT_EQ(GetTrustLevelName(TrustLevel::SystemRoot), "SystemRoot");
}

}  // namespace
