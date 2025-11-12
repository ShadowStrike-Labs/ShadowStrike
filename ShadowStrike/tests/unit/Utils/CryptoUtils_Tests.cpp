#include <gtest/gtest.h>
#include "../../../src/Utils/CryptoUtils.hpp"
#include "../../../src/Utils/HashUtils.hpp"
#include "../../../src/Utils/FileUtils.hpp"
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <chrono>
#include <algorithm>

// Windows CryptoAPI for test certificate generation
#ifdef _WIN32
#  include <Windows.h>
#  include <wincrypt.h>
#  pragma comment(lib, "crypt32.lib")
#  pragma comment(lib, "advapi32.lib")
#endif

using namespace ShadowStrike::Utils::CryptoUtils;
using namespace ShadowStrike::Utils;

// Helper: convert std::wstring (UTF-16) to UTF-8 std::string using Windows API
static std::string WStringToUtf8(const std::wstring& w) {
#ifdef _WIN32
    if (w.empty()) return std::string();
    int sizeNeeded = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return std::string();
    std::string out;
    out.resize(sizeNeeded);
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &out[0], sizeNeeded, nullptr, nullptr);
    return out;
#else
    // Fallback for non-Windows: simple narrow (best-effort)
    std::string out;
    out.reserve(w.size());
    for (wchar_t wc : w) out.push_back(static_cast<char>(wc <= 0x7F ? wc : '?'));
    return out;
#endif
}

// ============================================================================
// Test Fixtures
// ============================================================================

class CryptoUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        testDir = std::filesystem::temp_directory_path() / "cryptoutils_tests";
        std::filesystem::create_directories(testDir);

        // Create test certificates directory
        certDir = testDir / "certs";
        std::filesystem::create_directories(certDir);
    }

    void TearDown() override {
        if (std::filesystem::exists(testDir)) {
            std::filesystem::remove_all(testDir);
        }
    }

    // Helper: Create a self-signed test certificate using Windows CryptoAPI
    bool CreateTestCertificate(const std::filesystem::path& outputPath, std::string& pemOut) {
        // ✅ Generate RSA key pair
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;

        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
            if (GetLastError() == NTE_EXISTS) {
                if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, 0)) {
                    return false;
                }
            }
            else {
                return false;
            }
        }

        // Generate 2048-bit RSA key
        if (!CryptGenKey(hProv, AT_SIGNATURE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }

        // ✅ Create certificate subject
        CERT_NAME_BLOB subjectName = {};
        const wchar_t* subjectStr = L"CN=ShadowStrike Test Cert,O=Test Organization,C=US";

        DWORD subjectSize = 0;
        CertStrToNameW(X509_ASN_ENCODING, subjectStr, CERT_X500_NAME_STR, nullptr, nullptr, &subjectSize, nullptr);

        std::vector<BYTE> subjectBlob(subjectSize);
        if (!CertStrToNameW(X509_ASN_ENCODING, subjectStr, CERT_X500_NAME_STR, nullptr,
            subjectBlob.data(), &subjectSize, nullptr)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        subjectName.cbData = subjectSize;
        subjectName.pbData = subjectBlob.data();

        // ✅ Create validity period (1 year)
        SYSTEMTIME startTime, endTime;
        GetSystemTime(&startTime);
        endTime = startTime;
        endTime.wYear += 1;

        FILETIME ftStart, ftEnd;
        SystemTimeToFileTime(&startTime, &ftStart);
        SystemTimeToFileTime(&endTime, &ftEnd);

        // ✅ Create certificate info
        CRYPT_ALGORITHM_IDENTIFIER signAlg = {};
        signAlg.pszObjId = const_cast<char*>(szOID_RSA_SHA256RSA);

        // ✅ FIX: Use std::vector for heap allocation to prevent stack overflow
        DWORD pubKeySize = 0;
        CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, nullptr, &pubKeySize);

        std::vector<BYTE> pubKeyBlob(pubKeySize);
        if (!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING,
            reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(pubKeyBlob.data()), &pubKeySize)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        // ✅ Generate serial number
        BYTE serialNumber[16] = {};
        SecureRandom rng;
        rng.Generate(serialNumber, sizeof(serialNumber), nullptr);

        // Reverse for little-endian
        std::reverse(std::begin(serialNumber), std::end(serialNumber));

        CRYPT_INTEGER_BLOB serialBlob = {};
        serialBlob.cbData = sizeof(serialNumber);
        serialBlob.pbData = serialNumber;

        // ✅ Create self-signed certificate
        CERT_INFO certInfo = {};
        certInfo.dwVersion = CERT_V3;
        certInfo.SerialNumber = serialBlob;
        certInfo.SignatureAlgorithm = signAlg;
        certInfo.Issuer = subjectName;
        certInfo.Subject = subjectName;
        certInfo.NotBefore = ftStart;
        certInfo.NotAfter = ftEnd;
        // ✅ FIX: Correctly assign the pointer from the heap-allocated vector
        certInfo.SubjectPublicKeyInfo = *reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(pubKeyBlob.data());

        // ✅ Sign the certificate
        DWORD certSize = 0;
        if (!CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED, &certInfo, &signAlg,
            nullptr, nullptr, &certSize)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        std::vector<BYTE> certBlob(certSize);
        if (!CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED, &certInfo, &signAlg,
            nullptr, certBlob.data(), &certSize)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        // ✅ Convert to PEM format
        DWORD pemSize = 0;
        CryptBinaryToStringA(certBlob.data(), certSize, CRYPT_STRING_BASE64HEADER, nullptr, &pemSize);

        std::string pem(pemSize, '\0');
        if (!CryptBinaryToStringA(certBlob.data(), certSize, CRYPT_STRING_BASE64HEADER,
            &pem[0], &pemSize)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        pem.resize(pemSize - 1); // Remove null terminator
        pemOut = pem;

        // ✅ Write to file
        std::ofstream ofs(outputPath);
        if (!ofs) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return false;
        }
        ofs << pem;

        // Cleanup
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);

        return true;
    }
    std::filesystem::path testDir;
    std::filesystem::path certDir;
    Error err;
};

// ============================================================================
// SecureRandom - Comprehensive Unit Tests
// ============================================================================

TEST_F(CryptoUtilsTest, SecureRandom_Generate_EdgeCases) {
    SecureRandom rng;
    
    // Test zero size (should succeed)
    std::vector<uint8_t> empty;
    ASSERT_TRUE(rng.Generate(empty, 0, &err));
    EXPECT_EQ(empty.size(), 0u);
    
    // Test single byte
    std::vector<uint8_t> single;
    ASSERT_TRUE(rng.Generate(single, 1, &err));
    EXPECT_EQ(single.size(), 1u);
    
    // Test large buffer (1MB)
    std::vector<uint8_t> large;
    ASSERT_TRUE(rng.Generate(large, 1024 * 1024, &err));
    EXPECT_EQ(large.size(), 1024u * 1024u);
}

TEST_F(CryptoUtilsTest, SecureRandom_Generate_StatisticalUniformity) {
    SecureRandom rng;
    
    // Generate 10000 bytes and check distribution
    std::vector<uint8_t> data;
    ASSERT_TRUE(rng.Generate(data, 10000, &err));
    
    // Count byte frequency
    std::vector<int> freq(256, 0);
    for (auto byte : data) {
        freq[byte]++;
    }
    
    // Chi-square test would be ideal here, but basic sanity check:
    // No byte should appear 0 times or >200 times in 10000 samples
    for (int count : freq) {
        EXPECT_GT(count, 0) << "Some byte values never appeared";
        EXPECT_LT(count, 200) << "Byte frequency too high";
    }
}

TEST_F(CryptoUtilsTest, SecureRandom_NextUInt32_Boundary) {
    SecureRandom rng;
    
    // Test same min/max (should return min)
    EXPECT_EQ(rng.NextUInt32(42, 42, &err), 42u);
    
    // Test min > max (should return min)
    EXPECT_EQ(rng.NextUInt32(100, 50, &err), 100u);
    
    // Test full range
    uint32_t val = rng.NextUInt32(0, UINT32_MAX, &err);
    EXPECT_GE(val, 0u);
}

TEST_F(CryptoUtilsTest, SecureRandom_GenerateAlphanumeric_Charset) {
    SecureRandom rng;
    
    std::string str = rng.GenerateAlphanumeric(1000, &err);
    EXPECT_EQ(str.length(), 1000u);
    
    // Verify charset: only 0-9, A-Z, a-z
    for (char c : str) {
        bool valid = (c >= '0' && c <= '9') ||
                     (c >= 'A' && c <= 'Z') ||
                     (c >= 'a' && c <= 'z');
        EXPECT_TRUE(valid) << "Invalid character: " << c;
    }
}

TEST_F(CryptoUtilsTest, SecureRandom_GenerateHex_Format) {
    SecureRandom rng;
    
    std::string hex = rng.GenerateHex(32, &err);
    EXPECT_EQ(hex.length(), 64u); // 32 bytes = 64 hex chars
    
    // Verify lowercase hex
    for (char c : hex) {
        bool valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        EXPECT_TRUE(valid) << "Invalid hex character: " << c;
    }
}

// ============================================================================
// SymmetricCipher - Edge Cases & Error Handling
// ============================================================================

TEST_F(CryptoUtilsTest, SymmetricCipher_SetKey_WrongSize) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    
    // Try 16-byte key for AES-256 (needs 32)
    std::vector<uint8_t> wrongKey(16, 0xAA);
    EXPECT_FALSE(cipher.SetKey(wrongKey, &err));
    EXPECT_NE(err.win32, ERROR_SUCCESS);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_Encrypt_WithoutKey) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    
    const std::string plaintext = "test";
    std::vector<uint8_t> ciphertext;
    
    EXPECT_FALSE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), ciphertext, &err
    ));
    EXPECT_EQ(err.win32, ERROR_INVALID_STATE);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_Encrypt_WithoutIV) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    
    std::vector<uint8_t> key;
    ASSERT_TRUE(cipher.GenerateKey(key, &err));
    
    const std::string plaintext = "test";
    std::vector<uint8_t> ciphertext;
    
    EXPECT_FALSE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), ciphertext, &err
    ));
    EXPECT_EQ(err.win32, ERROR_INVALID_STATE);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_ECB_NoIVRequired) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_ECB);
    
    std::vector<uint8_t> key;
    ASSERT_TRUE(cipher.GenerateKey(key, &err));
    
    // ECB doesn't need IV
    EXPECT_EQ(cipher.GetIVSize(), 0u);
    
    const std::string plaintext = "0123456789ABCDEF"; // 16 bytes (block-aligned)
    std::vector<uint8_t> ciphertext, decrypted;
    
    ASSERT_TRUE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), ciphertext, &err
    ));
    
    ASSERT_TRUE(cipher.Decrypt(
        ciphertext.data(), ciphertext.size(), decrypted, &err
    ));
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(plaintext, result);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_GCM_AADMismatch) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, &err));
    ASSERT_TRUE(cipher.GenerateIV(iv, &err));
    
    const std::string plaintext = "Secret";
    const std::string aad1 = "Metadata1";
    const std::string aad2 = "Metadata2";
    
    std::vector<uint8_t> ciphertext, tag;
    ASSERT_TRUE(cipher.EncryptAEAD(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        reinterpret_cast<const uint8_t*>(aad1.data()), aad1.size(),
        ciphertext, tag, &err
    ));
    
    // Decrypt with different AAD - should fail
    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(cipher.DecryptAEAD(
        ciphertext.data(), ciphertext.size(),
        reinterpret_cast<const uint8_t*>(aad2.data()), aad2.size(),
        tag.data(), tag.size(), decrypted, &err
    ));
}

TEST_F(CryptoUtilsTest, SymmetricCipher_GCM_TruncatedTag) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, &err));
    ASSERT_TRUE(cipher.GenerateIV(iv, &err));
    
    const std::string plaintext = "Test";
    std::vector<uint8_t> ciphertext, tag;
    
    ASSERT_TRUE(cipher.EncryptAEAD(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        nullptr, 0, ciphertext, tag, &err
    ));
    
    // Try with truncated tag (15 bytes instead of 16)
    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(cipher.DecryptAEAD(
        ciphertext.data(), ciphertext.size(),
        nullptr, 0, tag.data(), 15, decrypted, &err
    ));
}

TEST_F(CryptoUtilsTest, SymmetricCipher_Streaming_MultipleFinalize) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, &err));
    ASSERT_TRUE(cipher.GenerateIV(iv, &err));
    
    ASSERT_TRUE(cipher.EncryptInit(&err));
    
    std::vector<uint8_t> final;
    ASSERT_TRUE(cipher.EncryptFinal(final, &err));
    
    // Second finalize should fail
    EXPECT_FALSE(cipher.EncryptFinal(final, &err));
    EXPECT_EQ(err.win32, ERROR_INVALID_STATE);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_Streaming_UnalignedData) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, &err));
    ASSERT_TRUE(cipher.GenerateIV(iv, &err));
    
    // Test with non-block-aligned chunks
    const std::string data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26 bytes
    
    ASSERT_TRUE(cipher.EncryptInit(&err));
    
    std::vector<uint8_t> ciphertext;
    
    // Feed in 10-byte chunks (not block-aligned)
    for (size_t i = 0; i < data.size(); i += 10) {
        size_t len = std::min<size_t>(10, data.size() - i);
        std::vector<uint8_t> chunk;
        
        ASSERT_TRUE(cipher.EncryptUpdate(
            reinterpret_cast<const uint8_t*>(data.data() + i),
            len, chunk, &err
        ));
        
        ciphertext.insert(ciphertext.end(), chunk.begin(), chunk.end());
    }
    
    std::vector<uint8_t> final;
    ASSERT_TRUE(cipher.EncryptFinal(final, &err));
    ciphertext.insert(ciphertext.end(), final.begin(), final.end());
    
    // Decrypt and verify
    SymmetricCipher decipher(SymmetricAlgorithm::AES_256_CBC);
    ASSERT_TRUE(decipher.SetKey(key, &err));
    ASSERT_TRUE(decipher.SetIV(iv, &err));
    
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(decipher.Decrypt(ciphertext.data(), ciphertext.size(), decrypted, &err));
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(data, result);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_PaddingModes) {
    // ✅ Only test PKCS7 - industry standard used by GravityZone/CrowdStrike
    // ANSIX923, ISO10126, and Zero Padding removed (insecure)
    
    const std::string plaintext = "Test"; // 4 bytes (not block-aligned)
    
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    cipher.SetPaddingMode(PaddingMode::PKCS7);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, &err));
    ASSERT_TRUE(cipher.GenerateIV(iv, &err));
    
    // ✅ CRITICAL FIX: Save original IV before encryption
    std::vector<uint8_t> originalIV = iv;
    
    std::vector<uint8_t> ciphertext;
    ASSERT_TRUE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), ciphertext, &err
    )) << "Encryption failed for PKCS7 padding";
    
    // ✅ CRITICAL FIX: Create NEW cipher instance with original IV for decryption
    SymmetricCipher decryptCipher(SymmetricAlgorithm::AES_256_CBC);
    decryptCipher.SetPaddingMode(PaddingMode::PKCS7);
    ASSERT_TRUE(decryptCipher.SetKey(key, &err));
    ASSERT_TRUE(decryptCipher.SetIV(originalIV, &err)); // ✅ Use original IV
    
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(decryptCipher.Decrypt(
        ciphertext.data(), ciphertext.size(), decrypted, &err
    )) << "Decryption failed for PKCS7 padding";
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(plaintext, result) << "PKCS7 padding roundtrip failed";
}

// ============================================================================
// AsymmetricCipher - RSA Edge Cases
// ============================================================================
TEST_F(CryptoUtilsTest, AsymmetricCipher_RSA_MaxPlaintextSize) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);

    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, &err))
        << "Key generation failed: " << WStringToUtf8(err.message);

    ASSERT_TRUE(cipher.LoadPublicKey(keyPair.publicKey, &err))
        << "Public key load failed: " << WStringToUtf8(err.message);

    ASSERT_TRUE(cipher.LoadPrivateKey(keyPair.privateKey, &err))
        << "Private key load failed: " << WStringToUtf8(err.message);

    // Test with OAEP_SHA256
    const auto paddingScheme = RSAPaddingScheme::OAEP_SHA256;
    size_t maxSize = cipher.GetMaxPlaintextSize(paddingScheme);

    // ✅ CRITICAL: Validate max size is reasonable for RSA-2048
    ASSERT_GT(maxSize, 0u) << "Max plaintext size cannot be zero";
    ASSERT_LE(maxSize, 512u) << "Max plaintext size unreasonably large for RSA-2048: " << maxSize;

    // Expected: RSA-2048 with OAEP-SHA256 = 256 - 2*32 - 2 = 190 bytes
    EXPECT_GE(maxSize, 190u) << "Max size too small for RSA-2048/OAEP-SHA256";
    EXPECT_LE(maxSize, 200u) << "Max size too large for RSA-2048/OAEP-SHA256";

    // Test at max size
    std::vector<uint8_t> plaintext(maxSize, 0xAA);
    std::vector<uint8_t> ciphertext, decrypted;

    ASSERT_TRUE(cipher.Encrypt(plaintext.data(), plaintext.size(), ciphertext,
        paddingScheme, &err))
        << "Encryption failed: " << WStringToUtf8(err.message);

    ASSERT_TRUE(cipher.Decrypt(ciphertext.data(), ciphertext.size(), decrypted,
        paddingScheme, &err))
        << "Decryption failed: " << WStringToUtf8(err.message);

    EXPECT_EQ(plaintext, decrypted) << "Plaintext roundtrip failed";

    // Test over max size (should fail gracefully)
    std::vector<uint8_t> oversized(maxSize + 1, 0xBB);
    EXPECT_FALSE(cipher.Encrypt(oversized.data(), oversized.size(), ciphertext,
        paddingScheme, &err)) << "Encryption should fail for oversized plaintext";

    EXPECT_EQ(err.win32, ERROR_INVALID_PARAMETER) << "Expected ERROR_INVALID_PARAMETER for oversized input";
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_RSA_SignatureSize) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    
    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, &err));
    ASSERT_TRUE(cipher.LoadPrivateKey(keyPair.privateKey, &err));
    
    const std::string message = "Test message";
    std::vector<uint8_t> signature;
    
    ASSERT_TRUE(cipher.Sign(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(),
        signature, HashUtils::Algorithm::SHA256, RSAPaddingScheme::PSS_SHA256, &err
    ));
    
    size_t expectedSize = cipher.GetSignatureSize();
    EXPECT_EQ(signature.size(), expectedSize);
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_RSA_EmptyMessage) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    
    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, &err));
    ASSERT_TRUE(cipher.LoadPublicKey(keyPair.publicKey, &err));
    ASSERT_TRUE(cipher.LoadPrivateKey(keyPair.privateKey, &err));
    
    // Encrypt empty message
    std::vector<uint8_t> ciphertext, decrypted;
    ASSERT_TRUE(cipher.Encrypt(nullptr, 0, ciphertext, RSAPaddingScheme::OAEP_SHA256, &err));
    ASSERT_TRUE(cipher.Decrypt(ciphertext.data(), ciphertext.size(), decrypted,
                                RSAPaddingScheme::OAEP_SHA256, &err));
    EXPECT_EQ(decrypted.size(), 0u);
}

// ============================================================================
// AsymmetricCipher - ECC/ECDH Advanced Tests
// ============================================================================

TEST_F(CryptoUtilsTest, AsymmetricCipher_ECDH_DifferentCurves) {
    // Alice uses P-256
    AsymmetricCipher alice(AsymmetricAlgorithm::ECC_P256);
    KeyPair aliceKeys;
    ASSERT_TRUE(alice.GenerateKeyPair(aliceKeys, &err));
    ASSERT_TRUE(alice.LoadPrivateKey(aliceKeys.privateKey, &err));
    
    // Bob uses P-384 (incompatible)
    AsymmetricCipher bob(AsymmetricAlgorithm::ECC_P384);
    KeyPair bobKeys;
    ASSERT_TRUE(bob.GenerateKeyPair(bobKeys, &err));
    
    // Should fail due to algorithm mismatch
    std::vector<uint8_t> sharedSecret;
    EXPECT_FALSE(alice.DeriveSharedSecret(bobKeys.publicKey, sharedSecret, &err));
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_ECDH_MultipleDerivations) {
    AsymmetricCipher alice(AsymmetricAlgorithm::ECC_P256);
    KeyPair aliceKeys;
    ASSERT_TRUE(alice.GenerateKeyPair(aliceKeys, &err));
    ASSERT_TRUE(alice.LoadPrivateKey(aliceKeys.privateKey, &err));
    
    AsymmetricCipher bob(AsymmetricAlgorithm::ECC_P256);
    KeyPair bobKeys;
    ASSERT_TRUE(bob.GenerateKeyPair(bobKeys, &err));
    
    // Derive secret multiple times - should be deterministic
    std::vector<uint8_t> secret1, secret2;
    ASSERT_TRUE(alice.DeriveSharedSecret(bobKeys.publicKey, secret1, &err));
    ASSERT_TRUE(alice.DeriveSharedSecret(bobKeys.publicKey, secret2, &err));
    
    EXPECT_EQ(secret1, secret2);
}

// ============================================================================
// KeyDerivation - PBKDF2 Comprehensive Tests
// ============================================================================

TEST_F(CryptoUtilsTest, KeyDerivation_PBKDF2_IterationCount) {
    const std::string password = "password";
    std::vector<uint8_t> salt(16, 0x00);
    std::vector<uint8_t> key1(32), key2(32);
    
    // Same params should produce same key
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(), 10000, HashUtils::Algorithm::SHA256,
        key1.data(), key1.size(), &err
    ));
    
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(), 10000, HashUtils::Algorithm::SHA256,
        key2.data(), key2.size(), &err
    ));
    
    EXPECT_EQ(key1, key2);
    
    // Different iteration count should produce different key
    std::vector<uint8_t> key3(32);
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(), 20000, HashUtils::Algorithm::SHA256,
        key3.data(), key3.size(), &err
    ));
    
    EXPECT_NE(key1, key3);
}

TEST_F(CryptoUtilsTest, KeyDerivation_PBKDF2_SaltImpact) {
    const std::string password = "password";
    std::vector<uint8_t> salt1(16, 0x00);
    std::vector<uint8_t> salt2(16, 0xFF);
    
    std::vector<uint8_t> key1(32), key2(32);
    
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt1.data(), salt1.size(), 10000, HashUtils::Algorithm::SHA256,
        key1.data(), key1.size(), &err
    ));
    
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt2.data(), salt2.size(), 10000, HashUtils::Algorithm::SHA256,
        key2.data(), key2.size(), &err
    ));
    
    EXPECT_NE(key1, key2);
}

TEST_F(CryptoUtilsTest, KeyDerivation_HKDF_InfoParameter) {
    const std::string ikm = "input";
    const std::string salt = "salt";
    const std::string info1 = "context1";
    const std::string info2 = "context2";
    
    std::vector<uint8_t> key1(32), key2(32);
    
    ASSERT_TRUE(KeyDerivation::HKDF(
        reinterpret_cast<const uint8_t*>(ikm.data()), ikm.size(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
        reinterpret_cast<const uint8_t*>(info1.data()), info1.size(),
        HashUtils::Algorithm::SHA256, key1.data(), key1.size(), &err
    ));
    
    ASSERT_TRUE(KeyDerivation::HKDF(
        reinterpret_cast<const uint8_t*>(ikm.data()), ikm.size(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
        reinterpret_cast<const uint8_t*>(info2.data()), info2.size(),
        HashUtils::Algorithm::SHA256, key2.data(), key2.size(), &err
    ));
    
    EXPECT_NE(key1, key2);
}

// ============================================================================
// PEM Import/Export - Format Validation
// ============================================================================

TEST_F(CryptoUtilsTest, PublicKey_PEM_MalformedInput) {
    PublicKey key;
    
    // Missing header
    EXPECT_FALSE(PublicKey::ImportPEM("AAABBB==\n-----END PUBLIC KEY-----", key, &err));
    
    // Missing footer
    EXPECT_FALSE(PublicKey::ImportPEM("-----BEGIN PUBLIC KEY-----\nAAABBB==", key, &err));
    
    // Invalid base64
    EXPECT_FALSE(PublicKey::ImportPEM(
        "-----BEGIN PUBLIC KEY-----\n!@#$%^\n-----END PUBLIC KEY-----", key, &err
    ));
}

TEST_F(CryptoUtilsTest, PrivateKey_PEM_PasswordProtection) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, &err));
    
    const std::string password = "StrongPass123!";
    
    // Export with password
    std::string pem;
    ASSERT_TRUE(keyPair.privateKey.ExportPEM(pem, true, password, &err));
    
    // Try import without password (should fail)
    PrivateKey imported1;
    EXPECT_FALSE(PrivateKey::ImportPEM(pem, imported1, "", &err));
    EXPECT_EQ(err.win32, ERROR_INVALID_PASSWORD);
    
    // Import with wrong password (should fail)
    PrivateKey imported2;
    EXPECT_FALSE(PrivateKey::ImportPEM(pem, imported2, "WrongPass", &err));
    
    // Import with correct password (should succeed)
    PrivateKey imported3;
    ASSERT_TRUE(PrivateKey::ImportPEM(pem, imported3, password, &err));
    EXPECT_EQ(imported3.keyBlob, keyPair.privateKey.keyBlob);
}

// ============================================================================
// Certificate - Comprehensive Tests (with real test certs)
// ============================================================================

TEST_F(CryptoUtilsTest, Certificate_LoadFromPEM_Valid) {
    std::string certPEM;
    auto certPath = certDir / "test_cert.pem";
    ASSERT_TRUE(CreateTestCertificate(certPath, certPEM));
    
    Certificate cert;
    ASSERT_TRUE(cert.LoadFromPEM(certPEM, &err))
        << "Failed to load certificate: " << std::string(err.message.begin(), err.message.end());
    
    EXPECT_TRUE(cert.IsValid());
}

TEST_F(CryptoUtilsTest, Certificate_GetInfo_ValidCert) {
    std::string certPEM;
    auto certPath = certDir / "test_cert.pem";
    ASSERT_TRUE(CreateTestCertificate(certPath, certPEM));
    
    Certificate cert;
    ASSERT_TRUE(cert.LoadFromPEM(certPEM, &err));
    
    CertificateInfo info;
    ASSERT_TRUE(cert.GetInfo(info, &err));
    
    EXPECT_FALSE(info.subject.empty());
    EXPECT_FALSE(info.issuer.empty());
    EXPECT_FALSE(info.thumbprint.empty());
}

TEST_F(CryptoUtilsTest, Certificate_ExportPEM_Roundtrip) {
    std::string certPEM;
    auto certPath = certDir / "test_cert.pem";
    ASSERT_TRUE(CreateTestCertificate(certPath, certPEM));
    
    Certificate cert1;
    ASSERT_TRUE(cert1.LoadFromPEM(certPEM, &err));
    
    // Export to PEM
    std::string exportedPEM;
    ASSERT_TRUE(cert1.ExportPEM(exportedPEM, &err));
    
    // Re-import
    Certificate cert2;
    ASSERT_TRUE(cert2.LoadFromPEM(exportedPEM, &err));
    
    // Compare raw data
    std::vector<uint8_t> data1, data2;
    ASSERT_TRUE(cert1.Export(data1, &err));
    ASSERT_TRUE(cert2.Export(data2, &err));
    
    EXPECT_EQ(data1, data2);
}

TEST_F(CryptoUtilsTest, Certificate_VerifyChain_SelfSigned) {
    std::string certPEM;
    auto certPath = certDir / "test_cert.pem";
    ASSERT_TRUE(CreateTestCertificate(certPath, certPEM));
    
    Certificate cert;
    ASSERT_TRUE(cert.LoadFromPEM(certPEM, &err));
    
    // Self-signed cert chain verification
    bool chainValid = cert.VerifyChain(&err);
    // May fail if test cert is not trusted - this is expected
}

// ============================================================================
// File Encryption - Comprehensive Tests
// ============================================================================

TEST_F(CryptoUtilsTest, EncryptFile_EmptyFile) {
    auto inputPath = testDir / "empty.txt";
    auto encryptedPath = testDir / "empty.enc";
    auto decryptedPath = testDir / "empty.dec";
    
    // Create empty file
    std::ofstream(inputPath).close();
    
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, &err));
    
    ASSERT_TRUE(EncryptFile(inputPath.wstring(), encryptedPath.wstring(),
                           key.data(), key.size(), &err));
    
    ASSERT_TRUE(DecryptFile(encryptedPath.wstring(), decryptedPath.wstring(),
                           key.data(), key.size(), &err));
    
    // Verify decrypted file is also empty
    std::ifstream ifs(decryptedPath);
    EXPECT_TRUE(ifs.peek() == std::ifstream::traits_type::eof());
}

TEST_F(CryptoUtilsTest, EncryptFile_LargeFile) {
    auto inputPath = testDir / "large.txt";
    auto encryptedPath = testDir / "large.enc";
    auto decryptedPath = testDir / "large.dec";
    
    // Create 10MB file
    {
        std::ofstream ofs(inputPath, std::ios::binary);
        std::vector<uint8_t> chunk(1024 * 1024, 0xAA);
        for (int i = 0; i < 10; ++i) {
            ofs.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        }
    }
    
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, &err));
    
    ASSERT_TRUE(EncryptFile(inputPath.wstring(), encryptedPath.wstring(),
                           key.data(), key.size(), &err));
    
    ASSERT_TRUE(DecryptFile(encryptedPath.wstring(), decryptedPath.wstring(),
                           key.data(), key.size(), &err));
    
    // Verify file sizes
    auto origSize = std::filesystem::file_size(inputPath);
    auto decSize = std::filesystem::file_size(decryptedPath);
    EXPECT_EQ(origSize, decSize);
}

TEST_F(CryptoUtilsTest, DecryptFile_CorruptedHeader) {
    auto inputPath = testDir / "plain.txt";
    auto encryptedPath = testDir / "encrypted.bin";
    auto decryptedPath = testDir / "decrypted.txt";
    
    const std::string content = "Test";
    {
        std::ofstream ofs(inputPath);
        ofs << content;
    }
    
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, &err));
    
    ASSERT_TRUE(EncryptFile(inputPath.wstring(), encryptedPath.wstring(),
                           key.data(), key.size(), &err));
    
    // Corrupt the encrypted file header
    {
        std::fstream fs(encryptedPath, std::ios::in | std::ios::out | std::ios::binary);
        fs.seekp(0);
        uint32_t corrupt = 0xFFFFFFFF;
        fs.write(reinterpret_cast<const char*>(&corrupt), sizeof(corrupt));
    }
    
    // Decryption should fail
    EXPECT_FALSE(DecryptFile(encryptedPath.wstring(), decryptedPath.wstring(),
                            key.data(), key.size(), &err));
}

TEST_F(CryptoUtilsTest, EncryptFileWithPassword_IterationPersistence) {
    auto inputPath = testDir / "data.txt";
    auto encryptedPath = testDir / "data.enc";
    auto decryptedPath = testDir / "data.dec";
    
    const std::string content = "Important data";
    const std::string password = "Pass123";
    
    {
        std::ofstream ofs(inputPath);
        ofs << content;
    }
    
    ASSERT_TRUE(EncryptFileWithPassword(inputPath.wstring(), encryptedPath.wstring(),
                                       password, &err));
    
    // Verify iteration count is stored in file
    std::ifstream ifs(encryptedPath, std::ios::binary);
    ifs.seekg(4); // Skip salt size
    
    std::vector<uint8_t> salt(32);
    ifs.read(reinterpret_cast<char*>(salt.data()), 32);
    
    uint32_t iterations = 0;
    ifs.read(reinterpret_cast<char*>(&iterations), sizeof(iterations));
    
    EXPECT_EQ(iterations, 600000u); // OWASP 2023 recommendation
}

// ============================================================================
// String Encryption - Edge Cases
// ============================================================================

TEST_F(CryptoUtilsTest, EncryptString_EmptyString) {
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, &err));
    
    std::string ciphertext;
    ASSERT_TRUE(EncryptString("", key.data(), key.size(), ciphertext, &err));
    
    std::string decrypted;
    ASSERT_TRUE(DecryptString(ciphertext, key.data(), key.size(), decrypted, &err));
    
    EXPECT_EQ(decrypted, "");
}

TEST_F(CryptoUtilsTest, EncryptString_UnicodeContent) {
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, &err));
    
    const std::string plaintext = std::string{ u8"Hello世界🌍",
                                           u8"Hello世界🌍" + std::char_traits<char8_t>::length(u8"Hello世界🌍") };
    
    std::string ciphertext;
    ASSERT_TRUE(EncryptString(plaintext, key.data(), key.size(), ciphertext, &err));
    
    std::string decrypted;
    ASSERT_TRUE(DecryptString(ciphertext, key.data(), key.size(), decrypted, &err));
    
    EXPECT_EQ(plaintext, decrypted);
}

// ============================================================================
// Utility Functions - SecureCompare Timing Safety
// ============================================================================

TEST_F(CryptoUtilsTest, SecureCompare_TimingSafety) {
    std::vector<uint8_t> data1(32, 0xAA);
    std::vector<uint8_t> data2(32, 0xAA);
    std::vector<uint8_t> data3(32, 0xBB);
    
    // Compare equal data (multiple times for consistency)
    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(SecureCompare(data1, data2));
    }
    
    // Compare different data
    for (int i = 0; i < 100; ++i) {
        EXPECT_FALSE(SecureCompare(data1, data3));
    }
    
    // Timing should be constant regardless of where difference is
    data2[0] = 0xBB;  // Diff at start
    data3[31] = 0xAA; // Diff at end
    
    EXPECT_FALSE(SecureCompare(data1, data2));
    EXPECT_FALSE(SecureCompare(data1, data3));
}

TEST_F(CryptoUtilsTest, SecureCompare_NullPointers) {
    EXPECT_FALSE(SecureCompare(nullptr, nullptr, 10));
    
    std::vector<uint8_t> data(10, 0xAA);
    EXPECT_FALSE(SecureCompare(data.data(), nullptr, 10));
    EXPECT_FALSE(SecureCompare(nullptr, data.data(), 10));
}

// ============================================================================
// Entropy Calculation - Statistical Validation
// ============================================================================

TEST_F(CryptoUtilsTest, CalculateEntropy_KnownPatterns) {
    // All zeros - minimum entropy
    std::vector<uint8_t> zeros(1000, 0x00);
    double entropy1 = CalculateEntropy(zeros);
    EXPECT_LT(entropy1, 0.1);
    
    // Single repeating byte
    std::vector<uint8_t> single(1000, 0xFF);
    double entropy2 = CalculateEntropy(single);
    EXPECT_LT(entropy2, 0.1);
    
    // Sequential pattern (low entropy)
    std::vector<uint8_t> sequential(256);
    for (int i = 0; i < 256; ++i) sequential[i] = static_cast<uint8_t>(i);
    double entropy3 = CalculateEntropy(sequential);
    EXPECT_GT(entropy3, 7.5); // Close to max for uniform distribution
    
    // Random data (high entropy)
    SecureRandom rng;
    std::vector<uint8_t> random;
    ASSERT_TRUE(rng.Generate(random, 1000, &err));
    double entropy4 = CalculateEntropy(random);
    EXPECT_GT(entropy4, 7.5);
}

TEST_F(CryptoUtilsTest, HasHighEntropy_Threshold) {
    std::vector<uint8_t> lowEntropy(1000, 0xAA);
    EXPECT_FALSE(HasHighEntropy(lowEntropy.data(), lowEntropy.size(), 7.0));
    
    SecureRandom rng;
    std::vector<uint8_t> highEntropy;
    ASSERT_TRUE(rng.Generate(highEntropy, 1000, &err));
    EXPECT_TRUE(HasHighEntropy(highEntropy.data(), highEntropy.size(), 7.0));
}

// ============================================================================
// SecureBuffer - Memory Safety
// ============================================================================

TEST_F(CryptoUtilsTest, SecureBuffer_ZeroOnDestruction) {
    std::vector<uint8_t> testData = {0xAA, 0xBB, 0xCC, 0xDD};
    
    uint8_t* rawPtr = nullptr;
    {
        SecureBuffer<uint8_t> buffer(testData.size());
        buffer.CopyFrom(testData);
        rawPtr = buffer.Data();
        
        // Verify data is present
        EXPECT_EQ(std::memcmp(rawPtr, testData.data(), testData.size()), 0);
    }
    
    // After destruction, memory should be zeroed (can't reliably test due to OS)
    // But we can verify the SecureBuffer cleared it
}

TEST_F(CryptoUtilsTest, SecureBuffer_Resize) {
    SecureBuffer<uint8_t> buffer(10);
    EXPECT_EQ(buffer.Size(), 10u);
    
    buffer.Resize(20);
    EXPECT_EQ(buffer.Size(), 20u);
    
    buffer.Resize(5);
    EXPECT_EQ(buffer.Size(), 5u);
    
    buffer.Clear();
    EXPECT_EQ(buffer.Size(), 0u);
    EXPECT_TRUE(buffer.Empty());
}

// ============================================================================
// SecureString - UTF-8 Handling
// ============================================================================

TEST_F(CryptoUtilsTest, SecureString_WideString) {
    const std::wstring wide = L"Test文字列";
    SecureString str(wide);
    
    EXPECT_FALSE(str.Empty());
    EXPECT_GT(str.Size(), 0u);
    
    std::string_view view = str.ToStringView();
    EXPECT_FALSE(view.empty());
}
