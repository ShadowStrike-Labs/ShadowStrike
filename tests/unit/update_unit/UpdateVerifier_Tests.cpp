/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic UpdateVerifier contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <string>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Update/UpdateVerifier.hpp"
#include "Update_TestUtils.hpp"

namespace ShadowStrike::Update::Test {
namespace {

using nlohmann::json;

}  // namespace

TEST(UpdateVerifierTest, HelperNamesVersionFormattingAndHashingRemainStable) {
    EXPECT_EQ(GetVerificationStatusName(VerificationStatus::CertificateExpired), "CertificateExpired");
    EXPECT_EQ(GetSignatureAlgorithmName(SignatureAlgorithm::ECDSA_P384_SHA384), "ECDSA-P384-SHA384");
    EXPECT_EQ(GetCertificateTypeName(CertificateType::CodeSigning), "CodeSigning");
    EXPECT_EQ(GetRevocationMethodName(RevocationCheckMethod::Both), "Both");
    EXPECT_EQ(GetVerificationStatusName(static_cast<VerificationStatus>(0xFF)), "Unknown");

    const std::string versionString = UpdateVerifier::GetVersionString();
    EXPECT_FALSE(versionString.empty());
    EXPECT_EQ(std::count(versionString.begin(), versionString.end(), '.'), 3);

    const auto components = ParseVersion("3.14.159");
    EXPECT_EQ(components[0], 3u);
    EXPECT_EQ(components[1], 14u);
    EXPECT_EQ(components[2], 159u);
    EXPECT_EQ(components[3], 0u);
    EXPECT_EQ(FormatVersion(components), "3.14.159.0");

    ScopedTempDir tempDir(L"verifier_hash_");
    const auto filePath = tempDir.File(L"package.bin");
    WriteAllText(filePath, "ShadowStrike");

    const std::string hash = CalculateFileHash(filePath);
    EXPECT_EQ(hash.size(), 64u);
    EXPECT_TRUE(std::all_of(hash.begin(), hash.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    }));
}

TEST(UpdateVerifierTest, CertificateDtosStatisticsAndConfigurationRemainActionable) {
    const auto now = std::chrono::system_clock::now();

    CertificateInfo expired;
    expired.subjectName = "CN=Expired";
    expired.issuerName = "CN=ShadowStrike Root";
    expired.serialNumber = "01";
    expired.thumbprint = "thumb";
    expired.type = CertificateType::CodeSigning;
    expired.validFrom = now - std::chrono::hours(48);
    expired.validTo = now - std::chrono::hours(1);
    expired.keyAlgorithm = "RSA";
    expired.keySize = 4096;
    expired.isValid = false;
    expired.isTrusted = false;
    expired.isRevoked = false;
    EXPECT_TRUE(expired.IsExpired());

    CertificateInfo valid = expired;
    valid.subjectName = "CN=Valid";
    valid.validTo = now + std::chrono::hours(48);
    valid.isValid = true;
    valid.isTrusted = true;
    EXPECT_FALSE(valid.IsExpired());

    const json certificateJson = json::parse(valid.ToJson());
    EXPECT_EQ(certificateJson.at("subjectName"), "CN=Valid");
    EXPECT_EQ(certificateJson.at("keySize"), 4096);
    EXPECT_TRUE(certificateJson.at("isTrusted").get<bool>());

    SignatureInfo signatureInfo;
    signatureInfo.algorithm = SignatureAlgorithm::RSA_SHA256;
    signatureInfo.signerCertificate = valid;
    signatureInfo.certificateChain = {expired, valid};

    const json signatureJson = json::parse(signatureInfo.ToJson());
    EXPECT_EQ(signatureJson.at("algorithm"), "RSA-SHA256");
    EXPECT_EQ(signatureJson.at("chainLength"), 2);

    VerificationResult verification;
    verification.status = VerificationStatus::HashMismatch;
    verification.isValid = false;
    verification.filePath = "package.pkg";
    verification.expectedHash = "expected";
    verification.actualHash = "actual";
    verification.versionValidated = true;
    verification.errorMessage = "hash mismatch";
    verification.durationMs = 42;

    const json verificationJson = json::parse(verification.ToJson());
    EXPECT_EQ(verificationJson.at("status"), "HashMismatch");
    EXPECT_EQ(verificationJson.at("filePath"), "package.pkg");
    EXPECT_EQ(verificationJson.at("error"), "hash mismatch");

    PackageManifest manifest;
    manifest.packageId = "package";
    manifest.version = "1.2.3";
    manifest.files = {{"payload.bin", "abc123"}};
    manifest.totalSize = 1234;
    manifest.createdTime = now;
    manifest.minimumVersion = "1.0.0";
    manifest.signature = {0x01, 0x02};
    EXPECT_TRUE(manifest.IsValid());

    const json manifestJson = json::parse(manifest.ToJson());
    EXPECT_EQ(manifestJson.at("packageId"), "package");
    EXPECT_EQ(manifestJson.at("fileCount"), 1);

    manifest.signature.clear();
    EXPECT_FALSE(manifest.IsValid());

    PinnedCertificate pinned;
    pinned.subjectName = "CN=ShadowStrike";
    pinned.thumbprint = "thumbprint";
    pinned.publicKeyHash = "pubkey";
    pinned.expiryDate = now + std::chrono::hours(24);
    pinned.isBackup = true;

    const json pinnedJson = json::parse(pinned.ToJson());
    EXPECT_EQ(pinnedJson.at("subjectName"), "CN=ShadowStrike");
    EXPECT_TRUE(pinnedJson.at("isBackup").get<bool>());

    VerifierStatistics stats;
    stats.verificationsPerformed = 7;
    stats.verificationsSucceeded = 5;
    stats.verificationsFailed = 2;
    stats.signatureVerifications = 4;
    stats.hashVerifications = 3;
    stats.chainValidations = 2;
    stats.revocationChecks = 1;
    stats.downgradeAttempts = 6;
    stats.byStatus[static_cast<size_t>(VerificationStatus::HashMismatch)] = 9;

    stats.Reset();

    EXPECT_EQ(stats.verificationsPerformed, 0u);
    EXPECT_EQ(stats.verificationsFailed, 0u);
    EXPECT_EQ(stats.downgradeAttempts, 0u);
    EXPECT_EQ(stats.byStatus[static_cast<size_t>(VerificationStatus::HashMismatch)], 0u);

    const json statsJson = json::parse(stats.ToJson());
    EXPECT_EQ(statsJson.at("verificationsPerformed"), 0);
    EXPECT_EQ(statsJson.at("revocationChecks"), 0);

    UpdateVerifierConfiguration config;
    EXPECT_FALSE(config.IsValid());

    config.enableCertificatePinning = false;
    EXPECT_TRUE(config.IsValid());

    config.enableCertificatePinning = true;
    config.pinnedCertificates = {pinned};
    EXPECT_TRUE(config.IsValid());
}

TEST(UpdateVerifierTest, ParsingAndDefaultRuntimeStateRemainFailClosed) {
    EXPECT_EQ(ParseVersion(""), (std::array<uint32_t, 4>{0u, 0u, 0u, 0u}));
    EXPECT_EQ(ParseVersion("10.alpha.30"), (std::array<uint32_t, 4>{10u, 0u, 30u, 0u}));
    EXPECT_EQ(FormatVersion(ParseVersion("7..9")), "7.0.9.0");
    EXPECT_TRUE(CalculateFileHash(L"").empty());
    EXPECT_TRUE(CalculateFileHash(L"missing-package.bin").empty());

    auto& verifier = UpdateVerifier::Instance();
    verifier.Shutdown();

    EXPECT_FALSE(verifier.IsInitialized());
    EXPECT_EQ(verifier.GetStatus(), VerifierStatus::Uninitialized);
    EXPECT_TRUE(verifier.GetMinimumVersion().empty());
    EXPECT_TRUE(verifier.GetPinnedCertificates().empty());
    EXPECT_EQ(verifier.GetStatistics().verificationsPerformed, 0u);
    EXPECT_FALSE(verifier.ValidateVersionSequence("1.0.0"));
    const std::array<uint8_t, 1> data{1u};
    const std::array<uint8_t, 1> signature{2u};
    EXPECT_FALSE(verifier.VerifySignature(
        std::span<const uint8_t>(data),
        std::span<const uint8_t>(signature)));
}

TEST(UpdateVerifierTest, PinnedCertificateAndMinimumVersionPoliciesRemainMonotonic) {
    auto& verifier = UpdateVerifier::Instance();
    verifier.Shutdown();

    UpdateVerifierConfiguration config;
    config.enableCertificatePinning = false;
    config.enableAntiDowngrade = true;
    ASSERT_TRUE(config.IsValid());
    ASSERT_TRUE(verifier.Initialize(config));

    PinnedCertificate pinned;
    pinned.subjectName = "CN=ShadowStrike";
    pinned.thumbprint = "ABCDEF1234";
    pinned.publicKeyHash = "cafebabe";

    EXPECT_TRUE(verifier.AddPinnedCertificate(pinned));
    EXPECT_TRUE(verifier.AddPinnedCertificate(pinned));
    EXPECT_EQ(verifier.GetPinnedCertificates().size(), 1u);

    CertificateInfo cert;
    cert.thumbprint = "abcdef1234";
    EXPECT_TRUE(verifier.IsCertificatePinned(cert));
    EXPECT_TRUE(verifier.RemovePinnedCertificate("abcdef1234"));
    EXPECT_TRUE(verifier.GetPinnedCertificates().empty());
    EXPECT_FALSE(verifier.RemovePinnedCertificate("abcdef1234"));
    EXPECT_FALSE(verifier.AddPinnedCertificate(PinnedCertificate{}));

    verifier.SetMinimumVersion("2.0.0");
    verifier.SetMinimumVersion("1.9.9");
    EXPECT_EQ(verifier.GetMinimumVersion(), "2.0.0");
    EXPECT_FALSE(verifier.ValidateVersionSequence("1.9.9"));
    EXPECT_TRUE(verifier.ValidateVersionSequence("2.0.0"));

    verifier.Shutdown();
}

TEST(UpdateVerifierTest, RepeatedInitializePreservesPinnedCertificatesAndMinimumVersion) {
    auto& verifier = UpdateVerifier::Instance();
    verifier.Shutdown();

    PinnedCertificate initialPinned;
    initialPinned.subjectName = "CN=Initial";
    initialPinned.thumbprint = "ABC123";
    initialPinned.publicKeyHash = "feedface";

    UpdateVerifierConfiguration initialConfig;
    initialConfig.enableCertificatePinning = true;
    initialConfig.pinnedCertificates = {initialPinned};
    initialConfig.minimumVersion = "2.0.0";
    ASSERT_TRUE(initialConfig.IsValid());
    ASSERT_TRUE(verifier.Initialize(initialConfig));

    PinnedCertificate replacementPinned;
    replacementPinned.subjectName = "CN=Replacement";
    replacementPinned.thumbprint = "DEF456";
    replacementPinned.publicKeyHash = "deadbeef";

    UpdateVerifierConfiguration replacementConfig = initialConfig;
    replacementConfig.pinnedCertificates = {replacementPinned};
    replacementConfig.minimumVersion = "9.0.0";

    ASSERT_TRUE(verifier.Initialize(replacementConfig));

    EXPECT_EQ(verifier.GetMinimumVersion(), "2.0.0");
    const auto pinnedCertificates = verifier.GetPinnedCertificates();
    ASSERT_EQ(pinnedCertificates.size(), 1u);
    EXPECT_EQ(pinnedCertificates.front().thumbprint, "ABC123");

    verifier.Shutdown();
}

}  // namespace ShadowStrike::Update::Test
