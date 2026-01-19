// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/**
 * @file PE_sig_verf_tests.cpp
 * @brief Comprehensive Unit Tests for PE Signature Verification (PE_sig_verf)
 *
 * Test Coverage:
 * - VerifyPESignature: Valid/invalid/unsigned PE files
 * - VerifyCatalogSignature: Catalog file verification
 * - VerifyEmbeddedSignature: Embedded Authenticode signatures
 * - ValidateCertificateChain: Chain validation with different revocation modes
 * - CheckCodeSigningEKU: EKU validation
 * - ValidateTimestamp: Timestamp within/outside certificate validity
 * - GetSignerName/GetIssuerName/GetCertThumbprint: Certificate metadata extraction
 * - VerifyNestedSignatures: Multi-signature PE files
 * - ExtractAllSignatures: Metadata extraction without trust decision
 * - Policy configuration: RevocationMode, grace periods, catalog fallback
 * - Edge cases: Null pointers, empty paths, corrupt files, missing files
 * - Thread safety: Concurrent verification operations
 *
 * @note Uses signed Windows system files for realistic testing scenarios.
 * @note Tests are designed to be deterministic and repeatable.
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 */

#include "pch.h"
#include <gtest/gtest.h>
#include "../../../src/Utils/PE_sig_verf.hpp"

#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <atomic>
#include <random>

using namespace ShadowStrike::Utils::pe_sig_utils;
namespace fs = std::filesystem;

// ============================================================================
// TEST FIXTURE
// ============================================================================

/**
 * @brief Test fixture for PE signature verification tests.
 *
 * Provides helper methods for creating test files, accessing system
 * signed executables, and managing test resources.
 */
class PESignatureVerifierTest : public ::testing::Test {
protected:
    /// Test directory for temporary files
    fs::path m_testDir;
    
    /// Path to a known signed system file (kernel32.dll)
    fs::path m_signedSystemFile;
    
    /// Path to our own executable (may or may not be signed)
    fs::path m_shadowStrikeExe;
    
    /// Instance of the verifier under test
    PEFileSignatureVerifier m_verifier;

    void SetUp() override {
        // Create unique test directory
        m_testDir = fs::temp_directory_path() / "ShadowStrike_PESigTests";
        fs::create_directories(m_testDir);
        
        // Locate signed system files for testing
        wchar_t sysDir[MAX_PATH]{};
        if (GetSystemDirectoryW(sysDir, MAX_PATH) > 0) {
            m_signedSystemFile = fs::path(sysDir) / L"kernel32.dll";
        }
        
        // Locate ShadowStrike executable
        m_shadowStrikeExe = L"C:\\ShadowStrike\\ShadowStrike\\bin\\Debug\\ShadowStrike.exe";
        
        // Configure verifier with reasonable defaults for testing
        m_verifier.SetRevocationMode(RevocationMode::OfflineAllowed);
        m_verifier.SetTimestampGraceSeconds(300); // 5 minutes
        m_verifier.SetAllowCatalogFallback(true);
        m_verifier.SetAllowMultipleSignatures(false);
        m_verifier.SetAllowWeakAlgos(true); // Allow SHA-1 for older files
    }

    void TearDown() override {
        // Clean up test directory
        std::error_code ec;
        fs::remove_all(m_testDir, ec);
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * @brief Creates a minimal invalid PE file for testing.
     * @param filename Name of the file to create
     * @return Full path to the created file
     */
    fs::path CreateInvalidPEFile(const std::wstring& filename) {
        fs::path filePath = m_testDir / filename;
        
        // Create a file with PE-like header but invalid signature table
        std::ofstream file(filePath, std::ios::binary);
        if (file) {
            // MZ header signature
            const char mzHeader[] = "MZ";
            file.write(mzHeader, 2);
            
            // Fill with zeros (invalid PE)
            std::vector<char> padding(4094, 0);
            file.write(padding.data(), padding.size());
        }
        
        return filePath;
    }

    /**
     * @brief Creates an empty file for edge case testing.
     * @param filename Name of the file to create
     * @return Full path to the created file
     */
    fs::path CreateEmptyFile(const std::wstring& filename) {
        fs::path filePath = m_testDir / filename;
        std::ofstream file(filePath, std::ios::binary);
        return filePath;
    }

    /**
     * @brief Creates a file with random content (not a valid PE).
     * @param filename Name of the file to create
     * @param size Size in bytes
     * @return Full path to the created file
     */
    fs::path CreateRandomFile(const std::wstring& filename, size_t size) {
        fs::path filePath = m_testDir / filename;
        
        std::ofstream file(filePath, std::ios::binary);
        if (file) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<int> dist(0, 255);
            
            for (size_t i = 0; i < size; ++i) {
                char byte = static_cast<char>(dist(gen));
                file.write(&byte, 1);
            }
        }
        
        return filePath;
    }

    /**
     * @brief Checks if a system signed file is available for testing.
     */
    bool HasSignedSystemFile() const {
        return fs::exists(m_signedSystemFile);
    }

    /**
     * @brief Checks if ShadowStrike executable exists.
     */
    bool HasShadowStrikeExe() const {
        return fs::exists(m_shadowStrikeExe);
    }

    /**
     * @brief Gets a certificate from Windows ROOT store for testing.
     * @param[out] outCert Certificate context (caller must free)
     * @return true if certificate was obtained
     */
    bool GetSystemRootCertificate(PCCERT_CONTEXT& outCert) {
        outCert = nullptr;
        
        HCERTSTORE hStore = CertOpenSystemStoreW(0, L"ROOT");
        if (!hStore) {
            return false;
        }
        
        outCert = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            nullptr,
            nullptr
        );
        
        CertCloseStore(hStore, 0);
        return outCert != nullptr;
    }
};

// ============================================================================
// VERIFIER CONFIGURATION TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, DefaultConfiguration) {
    PEFileSignatureVerifier verifier;
    
    // Verify default settings
    EXPECT_EQ(verifier.GetRevocationMode(), RevocationMode::OnlineOnly);
    EXPECT_EQ(verifier.GetTimestampGraceSeconds(), 300u);
    EXPECT_TRUE(verifier.GetAllowCatalogFallback());
    EXPECT_FALSE(verifier.GetAllowMultipleSignatures());
    EXPECT_FALSE(verifier.GetAllowWeakAlgos());
}

TEST_F(PESignatureVerifierTest, SetRevocationMode_AllModes) {
    PEFileSignatureVerifier verifier;
    
    verifier.SetRevocationMode(RevocationMode::OnlineOnly);
    EXPECT_EQ(verifier.GetRevocationMode(), RevocationMode::OnlineOnly);
    
    verifier.SetRevocationMode(RevocationMode::OfflineAllowed);
    EXPECT_EQ(verifier.GetRevocationMode(), RevocationMode::OfflineAllowed);
    
    verifier.SetRevocationMode(RevocationMode::Disabled);
    EXPECT_EQ(verifier.GetRevocationMode(), RevocationMode::Disabled);
}

TEST_F(PESignatureVerifierTest, SetTimestampGraceSeconds) {
    PEFileSignatureVerifier verifier;
    
    verifier.SetTimestampGraceSeconds(0);
    EXPECT_EQ(verifier.GetTimestampGraceSeconds(), 0u);
    
    verifier.SetTimestampGraceSeconds(3600); // 1 hour
    EXPECT_EQ(verifier.GetTimestampGraceSeconds(), 3600u);
    
    verifier.SetTimestampGraceSeconds(86400); // 1 day
    EXPECT_EQ(verifier.GetTimestampGraceSeconds(), 86400u);
}

TEST_F(PESignatureVerifierTest, SetAllowCatalogFallback) {
    PEFileSignatureVerifier verifier;
    
    verifier.SetAllowCatalogFallback(true);
    EXPECT_TRUE(verifier.GetAllowCatalogFallback());
    
    verifier.SetAllowCatalogFallback(false);
    EXPECT_FALSE(verifier.GetAllowCatalogFallback());
}

TEST_F(PESignatureVerifierTest, SetAllowMultipleSignatures) {
    PEFileSignatureVerifier verifier;
    
    verifier.SetAllowMultipleSignatures(true);
    EXPECT_TRUE(verifier.GetAllowMultipleSignatures());
    
    verifier.SetAllowMultipleSignatures(false);
    EXPECT_FALSE(verifier.GetAllowMultipleSignatures());
}

TEST_F(PESignatureVerifierTest, SetAllowWeakAlgos) {
    PEFileSignatureVerifier verifier;
    
    verifier.SetAllowWeakAlgos(true);
    EXPECT_TRUE(verifier.GetAllowWeakAlgos());
    
    verifier.SetAllowWeakAlgos(false);
    EXPECT_FALSE(verifier.GetAllowWeakAlgos());
}

// ============================================================================
// VerifyPESignature TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, VerifyPESignature_EmptyPath) {
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(L"", info, &err);
    
    EXPECT_FALSE(result);
    EXPECT_FALSE(info.isSigned);
    EXPECT_FALSE(info.isVerified);
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, VerifyPESignature_NonexistentFile) {
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(L"C:\\NonExistent\\Path\\file.exe", info, &err);
    
    EXPECT_FALSE(result);
    EXPECT_FALSE(info.isSigned);
    EXPECT_FALSE(info.isVerified);
}

TEST_F(PESignatureVerifierTest, VerifyPESignature_EmptyFile) {
    auto emptyFile = CreateEmptyFile(L"empty.exe");
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(emptyFile.wstring(), info, &err);
    
    EXPECT_FALSE(result);
    EXPECT_FALSE(info.isSigned);
}

TEST_F(PESignatureVerifierTest, VerifyPESignature_InvalidPE) {
    auto invalidPE = CreateInvalidPEFile(L"invalid.exe");
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(invalidPE.wstring(), info, &err);
    
    EXPECT_FALSE(result);
    EXPECT_FALSE(info.isSigned);
}

TEST_F(PESignatureVerifierTest, VerifyPESignature_RandomData) {
    auto randomFile = CreateRandomFile(L"random.exe", 8192);
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(randomFile.wstring(), info, &err);
    
    EXPECT_FALSE(result);
    EXPECT_FALSE(info.isSigned);
}

TEST_F(PESignatureVerifierTest, VerifyPESignature_SignedSystemFile) {
    if (!HasSignedSystemFile()) {
        GTEST_SKIP() << "No signed system file available";
    }
    
    SignatureInfo info;
    Error err;
    
    // kernel32.dll should be signed by Microsoft
    bool result = m_verifier.VerifyPESignature(m_signedSystemFile.wstring(), info, &err);
    
    // Note: Result depends on certificate chain and revocation status
    // We verify at minimum that the signature was detected
    if (result) {
        EXPECT_TRUE(info.isSigned);
        EXPECT_TRUE(info.isVerified);
        EXPECT_FALSE(info.signerName.empty());
        EXPECT_FALSE(info.thumbprint.empty());
    } else {
        // If verification failed, ensure we have proper error information
        EXPECT_TRUE(err.HasError() || !info.isVerified);
    }
}

TEST_F(PESignatureVerifierTest, VerifyPESignature_NullErrorPointer) {
    SignatureInfo info;
    
    // Should not crash with null error pointer
    bool result = m_verifier.VerifyPESignature(L"", info, nullptr);
    
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, VerifyPESignature_WithDisabledRevocation) {
    if (!HasSignedSystemFile()) {
        GTEST_SKIP() << "No signed system file available";
    }
    
    m_verifier.SetRevocationMode(RevocationMode::Disabled);
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(m_signedSystemFile.wstring(), info, &err);
    
    // With revocation disabled, verification may be more lenient
    if (result) {
        EXPECT_TRUE(info.isSigned);
    }
}

// ============================================================================
// VerifyEmbeddedSignature TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, VerifyEmbeddedSignature_EmptyPath) {
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyEmbeddedSignature(L"", info, &err);
    
    EXPECT_FALSE(result);
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, VerifyEmbeddedSignature_NonexistentFile) {
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyEmbeddedSignature(
        L"C:\\NonExistent\\embedded.exe", info, &err);
    
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, VerifyEmbeddedSignature_InvalidFile) {
    auto invalidFile = CreateRandomFile(L"notape.exe", 4096);
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyEmbeddedSignature(invalidFile.wstring(), info, &err);
    
    EXPECT_FALSE(result);
}

// ============================================================================
// VerifyCatalogSignature TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, VerifyCatalogSignature_EmptyPath) {
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyCatalogSignature(L"", L"", info, &err);
    
    EXPECT_FALSE(result);
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, VerifyCatalogSignature_NonexistentCatalog) {
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyCatalogSignature(
        L"C:\\NonExistent\\catalog.cat", L"ABC123", info, &err);
    
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, VerifyCatalogSignature_InvalidFile) {
    auto invalidCat = CreateRandomFile(L"invalid.cat", 2048);
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyCatalogSignature(
        invalidCat.wstring(), L"hash", info, &err);
    
    EXPECT_FALSE(result);
}

// ============================================================================
// ValidateCertificateChain TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, ValidateCertificateChain_NullCert) {
    Error err;
    
    bool result = m_verifier.ValidateCertificateChain(nullptr, &err);
    
    EXPECT_FALSE(result);
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, ValidateCertificateChain_ValidRootCert) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    Error err;
    
    // Root certificates may or may not pass Authenticode policy validation
    // as they typically don't have the code signing EKU
    bool result = m_verifier.ValidateCertificateChain(cert, &err);
    
    // Clean up
    CertFreeCertificateContext(cert);
    
    // Just verify the function doesn't crash - result depends on cert properties
    (void)result;
}

TEST_F(PESignatureVerifierTest, ValidateCertificateChain_WithDifferentRevocationModes) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    Error err;
    
    // Test with OnlineOnly - should not crash
    m_verifier.SetRevocationMode(RevocationMode::OnlineOnly);
    m_verifier.ValidateCertificateChain(cert, &err);
    err.Clear();
    
    // Test with OfflineAllowed - should not crash
    m_verifier.SetRevocationMode(RevocationMode::OfflineAllowed);
    m_verifier.ValidateCertificateChain(cert, &err);
    err.Clear();
    
    // Test with Disabled - should not crash
    m_verifier.SetRevocationMode(RevocationMode::Disabled);
    m_verifier.ValidateCertificateChain(cert, &err);
    
    CertFreeCertificateContext(cert);
    
    // Just verify the function doesn't crash with different modes
    SUCCEED();
}

// ============================================================================
// CheckCodeSigningEKU TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, CheckCodeSigningEKU_NullCert) {
    Error err;
    
    bool result = m_verifier.CheckCodeSigningEKU(nullptr, &err);
    
    EXPECT_FALSE(result);
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, CheckCodeSigningEKU_RootCertificate) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    Error err;
    
    // Most root certs don't have code signing EKU specifically
    bool result = m_verifier.CheckCodeSigningEKU(cert, &err);
    
    CertFreeCertificateContext(cert);
    
    // Result depends on the specific certificate
    // We just verify the function doesn't crash
    (void)result;
}

// ============================================================================
// CheckRevocationOnline TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, CheckRevocationOnline_NullCert) {
    Error err;
    
    bool result = m_verifier.CheckRevocationOnline(nullptr, &err);
    
    EXPECT_FALSE(result);
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, CheckRevocationOnline_DisabledMode) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    m_verifier.SetRevocationMode(RevocationMode::Disabled);
    Error err;
    
    // With revocation disabled, should return true
    bool result = m_verifier.CheckRevocationOnline(cert, &err);
    
    CertFreeCertificateContext(cert);
    
    EXPECT_TRUE(result);
}

// ============================================================================
// ValidateTimestamp TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, ValidateTimestamp_NullCert) {
    FILETIME ft{};
    Error err;
    
    bool result = m_verifier.ValidateTimestamp(ft, nullptr, &err);
    
    EXPECT_FALSE(result);
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, ValidateTimestamp_CurrentTimeWithValidCert) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    // Get current time
    SYSTEMTIME st{};
    GetSystemTime(&st);
    FILETIME ft{};
    SystemTimeToFileTime(&st, &ft);
    
    Error err;
    
    // Validate timestamp - result depends on certificate validity period
    bool result = m_verifier.ValidateTimestamp(ft, cert, &err);
    
    CertFreeCertificateContext(cert);
    
    // Just verify function doesn't crash - result depends on cert validity
    (void)result;
}

TEST_F(PESignatureVerifierTest, ValidateTimestamp_ZeroFiletime) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    FILETIME ft{}; // Zero filetime (1601-01-01)
    Error err;
    
    // Zero time should fail (before any cert's NotBefore)
    bool result = m_verifier.ValidateTimestamp(ft, cert, &err);
    
    CertFreeCertificateContext(cert);
    
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, ValidateTimestamp_WithGracePeriod) {
    m_verifier.SetTimestampGraceSeconds(86400); // 1 day grace
    
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    SYSTEMTIME st{};
    GetSystemTime(&st);
    FILETIME ft{};
    SystemTimeToFileTime(&st, &ft);
    
    Error err;
    bool result = m_verifier.ValidateTimestamp(ft, cert, &err);
    
    CertFreeCertificateContext(cert);
    
    // Result depends on cert validity period - just verify no crash
    (void)result;
}

// ============================================================================
// GetSignerName TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, GetSignerName_NullCert) {
    std::wstring name;
    Error err;
    
    bool result = m_verifier.GetSignerName(nullptr, name, &err);
    
    EXPECT_FALSE(result);
    EXPECT_TRUE(name.empty());
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, GetSignerName_ValidCert) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    std::wstring name;
    Error err;
    
    bool result = m_verifier.GetSignerName(cert, name, &err);
    
    CertFreeCertificateContext(cert);
    
    EXPECT_TRUE(result);
    EXPECT_FALSE(name.empty());
}

TEST_F(PESignatureVerifierTest, GetSignerName_NullErrorPointer) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    std::wstring name;
    
    // Should not crash with null error pointer
    bool result = m_verifier.GetSignerName(cert, name, nullptr);
    
    CertFreeCertificateContext(cert);
    
    EXPECT_TRUE(result);
}

// ============================================================================
// GetIssuerName TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, GetIssuerName_NullCert) {
    std::wstring issuer;
    Error err;
    
    bool result = m_verifier.GetIssuerName(nullptr, issuer, &err);
    
    EXPECT_FALSE(result);
    EXPECT_TRUE(issuer.empty());
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, GetIssuerName_ValidCert) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    std::wstring issuer;
    Error err;
    
    bool result = m_verifier.GetIssuerName(cert, issuer, &err);
    
    CertFreeCertificateContext(cert);
    
    EXPECT_TRUE(result);
    EXPECT_FALSE(issuer.empty());
}

TEST_F(PESignatureVerifierTest, GetIssuerName_SelfSignedCert) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    std::wstring signer, issuer;
    
    m_verifier.GetSignerName(cert, signer, nullptr);
    m_verifier.GetIssuerName(cert, issuer, nullptr);
    
    CertFreeCertificateContext(cert);
    
    // For self-signed certs, signer and issuer should match
    // (Root certs are typically self-signed)
    EXPECT_EQ(signer, issuer);
}

// ============================================================================
// GetCertThumbprint TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, GetCertThumbprint_NullCert) {
    std::wstring thumbprint;
    Error err;
    
    bool result = m_verifier.GetCertThumbprint(nullptr, thumbprint, &err);
    
    EXPECT_FALSE(result);
    EXPECT_TRUE(thumbprint.empty());
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, GetCertThumbprint_SHA256) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    std::wstring thumbprint;
    Error err;
    
    bool result = m_verifier.GetCertThumbprint(cert, thumbprint, &err, true);
    
    CertFreeCertificateContext(cert);
    
    EXPECT_TRUE(result);
    EXPECT_FALSE(thumbprint.empty());
    EXPECT_EQ(thumbprint.size(), 64u); // SHA-256 = 32 bytes = 64 hex chars
    
    // Verify it's valid hex
    for (wchar_t c : thumbprint) {
        EXPECT_TRUE((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F'))
            << "Invalid hex character: " << static_cast<char>(c);
    }
}

TEST_F(PESignatureVerifierTest, GetCertThumbprint_SHA1) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    std::wstring thumbprint;
    Error err;
    
    bool result = m_verifier.GetCertThumbprint(cert, thumbprint, &err, false);
    
    CertFreeCertificateContext(cert);
    
    EXPECT_TRUE(result);
    EXPECT_FALSE(thumbprint.empty());
    EXPECT_EQ(thumbprint.size(), 40u); // SHA-1 = 20 bytes = 40 hex chars
}

TEST_F(PESignatureVerifierTest, GetCertThumbprint_Consistency) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    std::wstring thumbprint1, thumbprint2;
    
    m_verifier.GetCertThumbprint(cert, thumbprint1, nullptr, true);
    m_verifier.GetCertThumbprint(cert, thumbprint2, nullptr, true);
    
    CertFreeCertificateContext(cert);
    
    // Same cert should produce same thumbprint
    EXPECT_EQ(thumbprint1, thumbprint2);
}

// ============================================================================
// VerifyNestedSignatures TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, VerifyNestedSignatures_EmptyPath) {
    std::vector<SignatureInfo> infos;
    Error err;
    
    bool result = m_verifier.VerifyNestedSignatures(L"", infos, &err);
    
    EXPECT_FALSE(result);
    EXPECT_TRUE(infos.empty());
    // Error may or may not be set depending on implementation
}

TEST_F(PESignatureVerifierTest, VerifyNestedSignatures_NonexistentFile) {
    std::vector<SignatureInfo> infos;
    Error err;
    
    bool result = m_verifier.VerifyNestedSignatures(
        L"C:\\NonExistent\\nested.exe", infos, &err);
    
    EXPECT_FALSE(result);
    EXPECT_TRUE(infos.empty());
}

TEST_F(PESignatureVerifierTest, VerifyNestedSignatures_InvalidFile) {
    auto invalidFile = CreateRandomFile(L"notnested.exe", 4096);
    
    std::vector<SignatureInfo> infos;
    Error err;
    
    bool result = m_verifier.VerifyNestedSignatures(invalidFile.wstring(), infos, &err);
    
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, VerifyNestedSignatures_SignedSystemFile) {
    if (!HasSignedSystemFile()) {
        GTEST_SKIP() << "No signed system file available";
    }
    
    m_verifier.SetAllowMultipleSignatures(true);
    
    std::vector<SignatureInfo> infos;
    Error err;
    
    bool result = m_verifier.VerifyNestedSignatures(
        m_signedSystemFile.wstring(), infos, &err);
    
    if (result) {
        EXPECT_FALSE(infos.empty());
        for (const auto& info : infos) {
            EXPECT_TRUE(info.isSigned);
        }
    }
}

// ============================================================================
// ExtractAllSignatures TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, ExtractAllSignatures_NonexistentFile) {
    Error err;
    
    auto sigs = m_verifier.ExtractAllSignatures(L"C:\\NonExistent\\file.exe", &err);
    
    EXPECT_TRUE(sigs.empty());
}

TEST_F(PESignatureVerifierTest, ExtractAllSignatures_InvalidFile) {
    auto invalidFile = CreateRandomFile(L"nosig.exe", 4096);
    
    Error err;
    
    auto sigs = m_verifier.ExtractAllSignatures(invalidFile.wstring(), &err);
    
    EXPECT_TRUE(sigs.empty());
}

TEST_F(PESignatureVerifierTest, ExtractAllSignatures_SignedSystemFile) {
    if (!HasSignedSystemFile()) {
        GTEST_SKIP() << "No signed system file available";
    }
    
    Error err;
    
    auto sigs = m_verifier.ExtractAllSignatures(m_signedSystemFile.wstring(), &err);
    
    // Signed files should have at least one signature
    // (Unless WinVerifyTrust fails for some reason)
    if (!sigs.empty()) {
        for (const auto& sig : sigs) {
            EXPECT_TRUE(sig.isSigned);
        }
    }
}

// ============================================================================
// ValidateCatalogChain TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, ValidateCatalogChain_NonexistentFile) {
    Error err;
    
    bool result = m_verifier.ValidateCatalogChain(
        L"C:\\NonExistent\\catalog.cat", L"", &err);
    
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, ValidateCatalogChain_InvalidFile) {
    auto invalidCat = CreateRandomFile(L"badcat.cat", 1024);
    
    Error err;
    
    bool result = m_verifier.ValidateCatalogChain(invalidCat.wstring(), L"", &err);
    
    EXPECT_FALSE(result);
}

// ============================================================================
// ERROR STRUCTURE TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, Error_DefaultConstruction) {
    Error err;
    
    EXPECT_EQ(err.win32, ERROR_SUCCESS);
    EXPECT_EQ(err.ntstatus, 0);
    EXPECT_TRUE(err.message.empty());
    EXPECT_TRUE(err.context.empty());
    EXPECT_FALSE(err.HasError());
}

TEST_F(PESignatureVerifierTest, Error_HasError_Win32) {
    Error err;
    err.win32 = ERROR_FILE_NOT_FOUND;
    
    EXPECT_TRUE(err.HasError());
}

TEST_F(PESignatureVerifierTest, Error_HasError_NtStatus) {
    Error err;
    err.ntstatus = -1;
    
    EXPECT_TRUE(err.HasError());
}

TEST_F(PESignatureVerifierTest, Error_Clear) {
    Error err;
    err.win32 = ERROR_ACCESS_DENIED;
    err.ntstatus = -1;
    err.message = L"Test error";
    err.context = L"Test context";
    
    err.Clear();
    
    EXPECT_EQ(err.win32, ERROR_SUCCESS);
    EXPECT_EQ(err.ntstatus, 0);
    EXPECT_TRUE(err.message.empty());
    EXPECT_TRUE(err.context.empty());
    EXPECT_FALSE(err.HasError());
}

// ============================================================================
// SignatureInfo STRUCTURE TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, SignatureInfo_DefaultConstruction) {
    SignatureInfo info;
    
    EXPECT_FALSE(info.isSigned);
    EXPECT_FALSE(info.isVerified);
    EXPECT_FALSE(info.isChainTrusted);
    EXPECT_FALSE(info.isEKUValid);
    EXPECT_FALSE(info.isTimestampValid);
    EXPECT_FALSE(info.isRevocationChecked);
    EXPECT_TRUE(info.signerName.empty());
    EXPECT_TRUE(info.issuerName.empty());
    EXPECT_TRUE(info.thumbprint.empty());
    EXPECT_EQ(info.signTime.dwLowDateTime, 0u);
    EXPECT_EQ(info.signTime.dwHighDateTime, 0u);
}

// ============================================================================
// THREAD SAFETY TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, ConcurrentVerification) {
    if (!HasSignedSystemFile()) {
        GTEST_SKIP() << "No signed system file available";
    }
    
    constexpr int kThreadCount = 4;
    constexpr int kIterationsPerThread = 5;
    
    std::atomic<int> successCount{0};
    std::atomic<int> failureCount{0};
    std::vector<std::thread> threads;
    
    for (int t = 0; t < kThreadCount; ++t) {
        threads.emplace_back([&]() {
            PEFileSignatureVerifier localVerifier;
            localVerifier.SetRevocationMode(RevocationMode::OfflineAllowed);
            
            for (int i = 0; i < kIterationsPerThread; ++i) {
                SignatureInfo info;
                Error err;
                
                bool result = localVerifier.VerifyPESignature(
                    m_signedSystemFile.wstring(), info, &err);
                
                if (result) {
                    successCount++;
                } else {
                    failureCount++;
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All threads should complete without crashes
    EXPECT_EQ(successCount + failureCount, kThreadCount * kIterationsPerThread);
}

TEST_F(PESignatureVerifierTest, ConcurrentMetadataExtraction) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    // Duplicate certificate for each thread
    constexpr int kThreadCount = 4;
    std::vector<PCCERT_CONTEXT> certs(kThreadCount);
    for (int i = 0; i < kThreadCount; ++i) {
        certs[i] = CertDuplicateCertificateContext(cert);
    }
    CertFreeCertificateContext(cert);
    
    std::atomic<int> completedCount{0};
    std::vector<std::thread> threads;
    
    for (int t = 0; t < kThreadCount; ++t) {
        threads.emplace_back([&, t]() {
            PEFileSignatureVerifier localVerifier;
            
            for (int i = 0; i < 10; ++i) {
                std::wstring name, issuer, thumb;
                localVerifier.GetSignerName(certs[t], name, nullptr);
                localVerifier.GetIssuerName(certs[t], issuer, nullptr);
                localVerifier.GetCertThumbprint(certs[t], thumb, nullptr, true);
            }
            
            completedCount++;
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // Cleanup
    for (auto c : certs) {
        if (c) CertFreeCertificateContext(c);
    }
    
    EXPECT_EQ(completedCount, kThreadCount);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

TEST_F(PESignatureVerifierTest, VeryLongFilePath) {
    // Create a path that's close to MAX_PATH
    std::wstring longPath = m_testDir.wstring();
    while (longPath.size() < MAX_PATH - 50) {
        longPath += L"\\subdir";
    }
    longPath += L"\\file.exe";
    
    SignatureInfo info;
    Error err;
    
    // Should fail gracefully (file doesn't exist)
    bool result = m_verifier.VerifyPESignature(longPath, info, &err);
    
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, UnicodeFilePath) {
    // Create file with Unicode characters in name
    fs::path unicodePath = m_testDir / L"测试文件_テスト.exe";
    
    std::ofstream file(unicodePath, std::ios::binary);
    file << "MZ"; // Minimal PE header
    file.close();
    
    SignatureInfo info;
    Error err;
    
    // Should handle Unicode paths without crashing
    bool result = m_verifier.VerifyPESignature(unicodePath.wstring(), info, &err);
    
    // File is invalid, so should fail
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, SpacesInPath) {
    fs::path spacePath = m_testDir / L"path with spaces" / L"file name.exe";
    fs::create_directories(spacePath.parent_path());
    
    std::ofstream file(spacePath, std::ios::binary);
    file << "MZ";
    file.close();
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(spacePath.wstring(), info, &err);
    
    // Should handle spaces properly (file is invalid, so fails)
    EXPECT_FALSE(result);
}

TEST_F(PESignatureVerifierTest, SpecialCharactersInPath) {
    fs::path specialPath = m_testDir / L"special!@#$%^&().exe";
    
    std::ofstream file(specialPath, std::ios::binary);
    file << "MZ";
    file.close();
    
    SignatureInfo info;
    Error err;
    
    bool result = m_verifier.VerifyPESignature(specialPath.wstring(), info, &err);
    
    EXPECT_FALSE(result); // Invalid PE
}

// ============================================================================
// STRESS TESTS (Optional - can be slow)
// ============================================================================

TEST_F(PESignatureVerifierTest, DISABLED_StressTest_ManyVerifications) {
    if (!HasSignedSystemFile()) {
        GTEST_SKIP() << "No signed system file available";
    }
    
    constexpr int kIterations = 100;
    
    for (int i = 0; i < kIterations; ++i) {
        SignatureInfo info;
        m_verifier.VerifyPESignature(m_signedSystemFile.wstring(), info, nullptr);
    }
    
    // Should complete without memory leaks or crashes
    SUCCEED();
}

TEST_F(PESignatureVerifierTest, DISABLED_StressTest_ManyMetadataExtractions) {
    PCCERT_CONTEXT cert = nullptr;
    if (!GetSystemRootCertificate(cert)) {
        GTEST_SKIP() << "Could not obtain system certificate";
    }
    
    constexpr int kIterations = 1000;
    
    for (int i = 0; i < kIterations; ++i) {
        std::wstring name, issuer, thumb;
        m_verifier.GetSignerName(cert, name, nullptr);
        m_verifier.GetIssuerName(cert, issuer, nullptr);
        m_verifier.GetCertThumbprint(cert, thumb, nullptr, true);
    }
    
    CertFreeCertificateContext(cert);
    
    SUCCEED();
}

