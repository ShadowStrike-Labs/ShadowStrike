#include <gtest/gtest.h>
#include "../../../src/Utils/CryptoUtils.hpp"
#include "../../../src/Utils/HashUtils.hpp"
#include "../../../src/Utils/FileUtils.hpp"
#include"../../../src/Utils/Logger.hpp"
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <algorithm>

// Windows CryptoAPI for test certificate generation
#ifdef _WIN32
#  include <Windows.h>
#  include <wincrypt.h>  
#  include <wintrust.h>  
#  include <softpub.h>    
#  include <bcrypt.h>  
#  include <ncrypt.h>    
#  include <mscat.h>    
#  include <ntstatus.h>   

#  pragma comment(lib, "crypt32.lib")
#  pragma comment(lib, "wintrust.lib")
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#endif

using namespace ShadowStrike::Utils::CryptoUtils;
using namespace ShadowStrike::Utils;

// ============================================================================
// Helper Functions
// ============================================================================

static std::string WStringToUtf8(const std::wstring& w) {
#ifdef _WIN32
    if (w.empty()) return std::string();
    int sizeNeeded = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), 
        nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return std::string();
    std::string out;
    out.resize(sizeNeeded);
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), 
        &out[0], sizeNeeded, nullptr, nullptr);
    return out;
#else
    std::string out;
    out.reserve(w.size());
    for (wchar_t wc : w) out.push_back(static_cast<char>(wc <= 0x7F ? wc : '?'));
    return out;
#endif
}

// ============================================================================
// Test Fixture
// ============================================================================

class CryptoUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {

        if (!Logger::Instance().IsInitialized()) {
            std::cerr << "[TEST FATAL] Logger not initialized before test!\n";
            GTEST_SKIP() << "Logger not initialized";
        }

        testDir = std::filesystem::temp_directory_path() / "cryptoutils_tests";
        std::filesystem::create_directories(testDir);
        
        err = std::make_unique<Error>();
    }

    void TearDown() override {
        if (std::filesystem::exists(testDir)) {
            std::filesystem::remove_all(testDir);
        }
        err.reset(); // clear
    }

    std::filesystem::path testDir;
    std::unique_ptr<Error> err; 
};

// ============================================================================
// TIER 1: SecureRandom Tests
// ============================================================================

TEST_F(CryptoUtilsTest, SecureRandom_Generate_BasicFunctionality) {
    SecureRandom rng;
    
    std::vector<uint8_t> data;
    ASSERT_TRUE(rng.Generate(data, 32, err.get())) << WStringToUtf8(err->message);
    EXPECT_EQ(data.size(), 32u);
}

TEST_F(CryptoUtilsTest, SecureRandom_Generate_ZeroSize) {
    SecureRandom rng;
    
    std::vector<uint8_t> empty;
    ASSERT_TRUE(rng.Generate(empty, 0, err.get()));
    EXPECT_EQ(empty.size(), 0u);
}

TEST_F(CryptoUtilsTest, SecureRandom_Generate_LargeBuffer) {
    SecureRandom rng;
    
    std::vector<uint8_t> large;
    ASSERT_TRUE(rng.Generate(large, 1024 * 1024, err.get())); // 1MB
    EXPECT_EQ(large.size(), 1024u * 1024u);
}

TEST_F(CryptoUtilsTest, SecureRandom_NextUInt32_Range) {
    SecureRandom rng;
    
    // Test 100 samples in range [10, 50)
    for (int i = 0; i < 100; ++i) {
        uint32_t val = rng.NextUInt32(10, 50, err.get());
        EXPECT_GE(val, 10u);
        EXPECT_LT(val, 50u);
    }
}

TEST_F(CryptoUtilsTest, SecureRandom_NextUInt32_BoundaryConditions) {
    SecureRandom rng;
    
    // Same min/max should return min
    EXPECT_EQ(rng.NextUInt32(42, 42, err.get()), 42u);
    
    // Min > max should return min
    EXPECT_EQ(rng.NextUInt32(100, 50, err.get()), 100u);
}

TEST_F(CryptoUtilsTest, SecureRandom_GenerateAlphanumeric_CharsetValidation) {
    SecureRandom rng;
    
    std::string str = rng.GenerateAlphanumeric(1000, err.get());
    EXPECT_EQ(str.length(), 1000u);
    
    // Verify charset: only [0-9A-Za-z]
    for (char c : str) {
        bool valid = (c >= '0' && c <= '9') ||
                     (c >= 'A' && c <= 'Z') ||
                     (c >= 'a' && c <= 'z');
        EXPECT_TRUE(valid) << "Invalid character: " << c;
    }
}

TEST_F(CryptoUtilsTest, SecureRandom_GenerateHex_Format) {
    SecureRandom rng;
    
    std::string hex = rng.GenerateHex(32, err.get());
    EXPECT_EQ(hex.length(), 64u); // 32 bytes = 64 hex chars
    
    // Verify lowercase hex
    for (char c : hex) {
        bool valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        EXPECT_TRUE(valid) << "Invalid hex character: " << c;
    }
}

// ============================================================================
// TIER 2: SymmetricCipher Tests (AES-256-GCM)
// ============================================================================

TEST_F(CryptoUtilsTest, SymmetricCipher_AES256GCM_BasicEncryptDecrypt) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);

    std::vector<uint8_t> key, iv;
    EXPECT_TRUE(cipher.GenerateKey(key,err.get())) << WStringToUtf8(err->message);
    EXPECT_TRUE(cipher.GenerateIV(iv, err.get())) << WStringToUtf8(err->message);

    const std::string plaintext = "Top Secret Message";
    std::vector<uint8_t> ciphertext, tag;

    // Encrypt
    ASSERT_TRUE(cipher.EncryptAEAD(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        nullptr, 0, ciphertext, tag, err.get()
    )) << WStringToUtf8(err->message);

    
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(cipher.DecryptAEAD(
        ciphertext.data(), ciphertext.size(),
        nullptr, 0, tag.data(), tag.size(), decrypted, err.get()
    )) << WStringToUtf8(err->message);

    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(plaintext, result);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_AES256GCM_WithAAD) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, err.get()));
    ASSERT_TRUE(cipher.GenerateIV(iv, err.get()));
    
    const std::string plaintext = "Secret";
    const std::string aad = "Metadata";
    
    std::vector<uint8_t> ciphertext, tag;
    ASSERT_TRUE(cipher.EncryptAEAD(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
        ciphertext, tag, err.get()
    ));
    
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(cipher.DecryptAEAD(
        ciphertext.data(), ciphertext.size(),
        reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
        tag.data(), tag.size(), decrypted, err.get()
    ));
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(plaintext, result);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_AES256GCM_AADMismatch) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, err.get()));
    ASSERT_TRUE(cipher.GenerateIV(iv, err.get()));
    
    const std::string plaintext = "Secret";
    const std::string aad1 = "Metadata1";
    const std::string aad2 = "Metadata2";
    
    std::vector<uint8_t> ciphertext, tag;
    ASSERT_TRUE(cipher.EncryptAEAD(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        reinterpret_cast<const uint8_t*>(aad1.data()), aad1.size(),
        ciphertext, tag, err.get()
    ));
    
    // Decrypt with different AAD - should fail
    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(cipher.DecryptAEAD(
        ciphertext.data(), ciphertext.size(),
        reinterpret_cast<const uint8_t*>(aad2.data()), aad2.size(),
        tag.data(), tag.size(), decrypted, err.get()
    ));
}

TEST_F(CryptoUtilsTest, SymmetricCipher_AES256GCM_TruncatedTag) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, err.get()));
    ASSERT_TRUE(cipher.GenerateIV(iv, err.get()));
    
    const std::string plaintext = "Test";
    std::vector<uint8_t> ciphertext, tag;
    
    ASSERT_TRUE(cipher.EncryptAEAD(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        nullptr, 0, ciphertext, tag, err.get()
    ));
    
    // Try with truncated tag (15 bytes instead of 16)
    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(cipher.DecryptAEAD(
        ciphertext.data(), ciphertext.size(),
        nullptr, 0, tag.data(), 15, decrypted, err.get()
    ));
    EXPECT_EQ(err->win32, ERROR_INVALID_PARAMETER);
}

// ============================================================================
// TIER 3: SymmetricCipher Tests (AES-256-CBC)
// ============================================================================

TEST_F(CryptoUtilsTest, SymmetricCipher_AES256CBC_PKCS7Padding) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    cipher.SetPaddingMode(PaddingMode::PKCS7);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, err.get()));
    ASSERT_TRUE(cipher.GenerateIV(iv, err.get()));
    
    const std::string plaintext = "Test"; // 4 bytes (not block-aligned)
    
    // Save original IV
    std::vector<uint8_t> originalIV = iv;
    
    std::vector<uint8_t> ciphertext;
    ASSERT_TRUE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), ciphertext, err.get()
    )) << WStringToUtf8(err->message);
    
    // Create new cipher for decryption with original IV
    SymmetricCipher decryptCipher(SymmetricAlgorithm::AES_256_CBC);
    decryptCipher.SetPaddingMode(PaddingMode::PKCS7);
    ASSERT_TRUE(decryptCipher.SetKey(key, err.get()));
    ASSERT_TRUE(decryptCipher.SetIV(originalIV, err.get()));
    
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(decryptCipher.Decrypt(
        ciphertext.data(), ciphertext.size(), decrypted, err.get()
    )) << WStringToUtf8(err->message);
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(plaintext, result);
}

TEST_F(CryptoUtilsTest, SymmetricCipher_AES256CBC_StreamingEncryption) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    
    std::vector<uint8_t> key, iv;
    ASSERT_TRUE(cipher.GenerateKey(key, err.get()));
    ASSERT_TRUE(cipher.GenerateIV(iv, err.get()));
    
    const std::string data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26 bytes
    
    ASSERT_TRUE(cipher.EncryptInit(err.get()));
    
    std::vector<uint8_t> ciphertext;
    
    // Feed in 10-byte chunks (not block-aligned)
    for (size_t i = 0; i < data.size(); i += 10) {
        size_t len = std::min<size_t>(10, data.size() - i);
        std::vector<uint8_t> chunk;
        
        ASSERT_TRUE(cipher.EncryptUpdate(
            reinterpret_cast<const uint8_t*>(data.data() + i),
            len, chunk, err.get()
        ));
        
        ciphertext.insert(ciphertext.end(), chunk.begin(), chunk.end());
    }
    
    std::vector<uint8_t> final;
    ASSERT_TRUE(cipher.EncryptFinal(final, err.get()));
    ciphertext.insert(ciphertext.end(), final.begin(), final.end());
    
    // Decrypt and verify
    SymmetricCipher decipher(SymmetricAlgorithm::AES_256_CBC);
    ASSERT_TRUE(decipher.SetKey(key, err.get()));
    ASSERT_TRUE(decipher.SetIV(iv, err.get()));
    
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(decipher.Decrypt(ciphertext.data(), ciphertext.size(), decrypted, err.get()));
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(data, result);
}

// ============================================================================
// TIER 4: AsymmetricCipher Tests (RSA)
// ============================================================================

TEST_F(CryptoUtilsTest, AsymmetricCipher_RSA2048_KeyGeneration) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    
    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, err.get())) 
        << WStringToUtf8(err->message);
    
    EXPECT_FALSE(keyPair.publicKey.keyBlob.empty());
    EXPECT_FALSE(keyPair.privateKey.keyBlob.empty());
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_RSA2048_EncryptDecrypt) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    
    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, err.get()));
    ASSERT_TRUE(cipher.LoadPublicKey(keyPair.publicKey, err.get()));
    ASSERT_TRUE(cipher.LoadPrivateKey(keyPair.privateKey, err.get()));
    
    const std::string plaintext = "Hello RSA";
    std::vector<uint8_t> ciphertext, decrypted;
    
    ASSERT_TRUE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        ciphertext, RSAPaddingScheme::OAEP_SHA256, err.get()
    )) << WStringToUtf8(err->message);
    
    ASSERT_TRUE(cipher.Decrypt(
        ciphertext.data(), ciphertext.size(), decrypted,
        RSAPaddingScheme::OAEP_SHA256, err.get()
    )) << WStringToUtf8(err->message);
    
    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(plaintext, result);
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_RSA2048_MaxPlaintextSize) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    
    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, err.get()));
    ASSERT_TRUE(cipher.LoadPublicKey(keyPair.publicKey, err.get()));
    ASSERT_TRUE(cipher.LoadPrivateKey(keyPair.privateKey, err.get()));
    
    const auto paddingScheme = RSAPaddingScheme::OAEP_SHA256;
    size_t maxSize = cipher.GetMaxPlaintextSize(paddingScheme);
    
    ASSERT_GT(maxSize, 0u);
    ASSERT_LE(maxSize, 512u);
    
    // Expected: RSA-2048 with OAEP-SHA256 = 256 - 2*32 - 2 = 190 bytes
    EXPECT_GE(maxSize, 190u);
    EXPECT_LE(maxSize, 200u);
    
    // Test at max size
    std::vector<uint8_t> plaintext(maxSize, 0xAA);
    std::vector<uint8_t> ciphertext, decrypted;
    
    ASSERT_TRUE(cipher.Encrypt(plaintext.data(), plaintext.size(), ciphertext,
        paddingScheme, err.get()));
    
    ASSERT_TRUE(cipher.Decrypt(ciphertext.data(), ciphertext.size(), decrypted,
        paddingScheme, err.get()));
    
    EXPECT_EQ(plaintext, decrypted);
    
    // Test over max size (should fail)
    std::vector<uint8_t> oversized(maxSize + 1, 0xBB);
    EXPECT_FALSE(cipher.Encrypt(oversized.data(), oversized.size(), ciphertext,
        paddingScheme, err.get()));
    EXPECT_EQ(err->win32, ERROR_INVALID_PARAMETER);
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_RSA2048_SignVerify) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    
    KeyPair keyPair;
    ASSERT_TRUE(cipher.GenerateKeyPair(keyPair, err.get()));
    ASSERT_TRUE(cipher.LoadPrivateKey(keyPair.privateKey, err.get()));
    ASSERT_TRUE(cipher.LoadPublicKey(keyPair.publicKey, err.get()));
    
    const std::string message = "Sign this message";
    std::vector<uint8_t> signature;
    
    ASSERT_TRUE(cipher.Sign(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(),
        signature, HashUtils::Algorithm::SHA256, RSAPaddingScheme::PSS_SHA256, err.get()
    )) << WStringToUtf8(err->message);
    
    ASSERT_TRUE(cipher.Verify(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(),
        signature.data(), signature.size(),
        HashUtils::Algorithm::SHA256, RSAPaddingScheme::PSS_SHA256, err.get()
    )) << WStringToUtf8(err->message);
}

// ============================================================================
// TIER 5: AsymmetricCipher Tests (ECC/ECDH)
// ============================================================================

TEST_F(CryptoUtilsTest, AsymmetricCipher_ECDH_P256_KeyAgreement) {
    // Alice generates key pair
    AsymmetricCipher alice(AsymmetricAlgorithm::ECC_P256);
    KeyPair aliceKeys;
    ASSERT_TRUE(alice.GenerateKeyPair(aliceKeys, err.get()));
    ASSERT_TRUE(alice.LoadPrivateKey(aliceKeys.privateKey, err.get()));
    
    // Bob generates key pair
    AsymmetricCipher bob(AsymmetricAlgorithm::ECC_P256);
    KeyPair bobKeys;
    ASSERT_TRUE(bob.GenerateKeyPair(bobKeys, err.get()));
    ASSERT_TRUE(bob.LoadPrivateKey(bobKeys.privateKey, err.get()));
    
    // Alice derives shared secret
    std::vector<uint8_t> aliceSecret;
    ASSERT_TRUE(alice.DeriveSharedSecret(bobKeys.publicKey, aliceSecret, err.get()))
        << WStringToUtf8(err->message);
    
    // Bob derives shared secret
    std::vector<uint8_t> bobSecret;
    ASSERT_TRUE(bob.DeriveSharedSecret(aliceKeys.publicKey, bobSecret, err.get()))
        << WStringToUtf8(err->message);
    
    // Secrets should match
    EXPECT_EQ(aliceSecret, bobSecret);
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_ECDH_DifferentCurves) {
    AsymmetricCipher alice(AsymmetricAlgorithm::ECC_P256);
    KeyPair aliceKeys;
    ASSERT_TRUE(alice.GenerateKeyPair(aliceKeys, err.get()));
    ASSERT_TRUE(alice.LoadPrivateKey(aliceKeys.privateKey, err.get()));
    
    AsymmetricCipher bob(AsymmetricAlgorithm::ECC_P384);
    KeyPair bobKeys;
    ASSERT_TRUE(bob.GenerateKeyPair(bobKeys, err.get()));
    
    // Should fail due to algorithm mismatch
    std::vector<uint8_t> sharedSecret;
    EXPECT_FALSE(alice.DeriveSharedSecret(bobKeys.publicKey, sharedSecret, err.get()));
}

// ============================================================================
// TIER 6: KeyDerivation Tests
// ============================================================================

TEST_F(CryptoUtilsTest, KeyDerivation_PBKDF2_Basic) {
    const std::string password = "password";
    std::vector<uint8_t> salt(16, 0x00);
    std::vector<uint8_t> key1(32), key2(32);
    
    // Same params should produce same key
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(), 10000, HashUtils::Algorithm::SHA256,
        key1.data(), key1.size(), err.get()
    ));
    
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(), 10000, HashUtils::Algorithm::SHA256,
        key2.data(), key2.size(), err.get()
    ));
    
    EXPECT_EQ(key1, key2);
}

TEST_F(CryptoUtilsTest, KeyDerivation_PBKDF2_DifferentIterations) {
    const std::string password = "password";
    std::vector<uint8_t> salt(16, 0x00);
    std::vector<uint8_t> key1(32), key2(32);
    
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(), 10000, HashUtils::Algorithm::SHA256,
        key1.data(), key1.size(), err.get()
    ));
    
    ASSERT_TRUE(KeyDerivation::PBKDF2(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(), 20000, HashUtils::Algorithm::SHA256,
        key2.data(), key2.size(), err.get()
    ));
    
    EXPECT_NE(key1, key2);
}

TEST_F(CryptoUtilsTest, KeyDerivation_HKDF_WithInfo) {
    const std::string ikm = "input";
    const std::string salt = "salt";
    const std::string info1 = "context1";
    const std::string info2 = "context2";
    
    std::vector<uint8_t> key1(32), key2(32);
    
    ASSERT_TRUE(KeyDerivation::HKDF(
        reinterpret_cast<const uint8_t*>(ikm.data()), ikm.size(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
        reinterpret_cast<const uint8_t*>(info1.data()), info1.size(),
        HashUtils::Algorithm::SHA256, key1.data(), key1.size(), err.get()
    ));
    
    ASSERT_TRUE(KeyDerivation::HKDF(
        reinterpret_cast<const uint8_t*>(ikm.data()), ikm.size(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
        reinterpret_cast<const uint8_t*>(info2.data()), info2.size(),
        HashUtils::Algorithm::SHA256, key2.data(), key2.size(), err.get()
    ));
    
    EXPECT_NE(key1, key2);
}

// ============================================================================
// TIER 7: File Encryption Tests
// ============================================================================

TEST_F(CryptoUtilsTest, EncryptFile_DecryptFile_Roundtrip) {
    auto inputPath = testDir / "plain.txt";
    auto encryptedPath = testDir / "encrypted.bin";
    auto decryptedPath = testDir / "decrypted.txt";
    
    const std::string content = "Top Secret Data";
    {
        std::ofstream ofs(inputPath);
        ofs << content;
    }
    
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, err.get()));
    
    ASSERT_TRUE(EncryptFile(inputPath.wstring(), encryptedPath.wstring(),
                           key.data(), key.size(), err.get()))
        << WStringToUtf8(err->message);
    
    ASSERT_TRUE(DecryptFile(encryptedPath.wstring(), decryptedPath.wstring(),
                           key.data(), key.size(), err.get()))
        << WStringToUtf8(err->message);
    
    std::ifstream ifs(decryptedPath);
    std::string result((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
    
    EXPECT_EQ(content, result);
}

TEST_F(CryptoUtilsTest, EncryptFileWithPassword_Roundtrip) {
    auto inputPath = testDir / "data.txt";
    auto encryptedPath = testDir / "data.enc";
    auto decryptedPath = testDir / "data.dec";
    
    const std::string content = "Password Protected";
    const std::string password = "StrongPass123!";
    
    {
        std::ofstream ofs(inputPath);
        ofs << content;
    }
    
    ASSERT_TRUE(EncryptFileWithPassword(inputPath.wstring(), encryptedPath.wstring(),
                                       password, err.get()))
        << WStringToUtf8(err->message);
    
    ASSERT_TRUE(DecryptFileWithPassword(encryptedPath.wstring(), decryptedPath.wstring(),
                                       password, err.get()))
        << WStringToUtf8(err->message);
    
    std::ifstream ifs(decryptedPath);
    std::string result((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
    
    EXPECT_EQ(content, result);
}

// ============================================================================
// TIER 8: String Encryption Tests
// ============================================================================

TEST_F(CryptoUtilsTest, EncryptString_DecryptString_Roundtrip) {
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, err.get()));
    
    const std::string plaintext = "Secret Message";
    std::string ciphertext;
    
    ASSERT_TRUE(EncryptString(plaintext, key.data(), key.size(), ciphertext, err.get()))
        << WStringToUtf8(err->message);
    
    std::string decrypted;
    ASSERT_TRUE(DecryptString(ciphertext, key.data(), key.size(), decrypted, err.get()))
        << WStringToUtf8(err->message);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CryptoUtilsTest, EncryptString_EmptyString) {
    SecureRandom rng;
    std::vector<uint8_t> key;
    ASSERT_TRUE(rng.Generate(key, 32, err.get()));
    
    std::string ciphertext;
    ASSERT_TRUE(EncryptString("", key.data(), key.size(), ciphertext, err.get()));
    
    std::string decrypted;
    ASSERT_TRUE(DecryptString(ciphertext, key.data(), key.size(), decrypted, err.get()));
    
    EXPECT_EQ(decrypted, "");
}

// ============================================================================
// TIER 9: Utility Functions Tests
// ============================================================================

TEST_F(CryptoUtilsTest, SecureCompare_TimingSafety) {
    std::vector<uint8_t> data1(32, 0xAA);
    std::vector<uint8_t> data2(32, 0xAA);
    std::vector<uint8_t> data3(32, 0xBB);
    
    EXPECT_TRUE(SecureCompare(data1, data2));
    EXPECT_FALSE(SecureCompare(data1, data3));
    
    // Different size
    std::vector<uint8_t> data4(16, 0xAA);
    EXPECT_FALSE(SecureCompare(data1, data4));
}


// ============================================================================
// TIER 10: Error Handling Tests
// ============================================================================

TEST_F(CryptoUtilsTest, Error_Structure_Functionality) {
    Error error;
    
    EXPECT_FALSE(error.HasError());
    
    error.win32 = ERROR_ACCESS_DENIED;
    error.message = L"Access denied";
    
    EXPECT_TRUE(error.HasError());
    EXPECT_EQ(error.win32, ERROR_ACCESS_DENIED);
    
    error.Clear();
    
    EXPECT_FALSE(error.HasError());
    EXPECT_EQ(error.win32, ERROR_SUCCESS);
    EXPECT_TRUE(error.message.empty());
}

TEST_F(CryptoUtilsTest, SymmetricCipher_ErrorHandling_KeyNotSet) {
    SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
    
    const std::string plaintext = "test";
    std::vector<uint8_t> ciphertext;
    
    EXPECT_FALSE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), ciphertext, err.get()
    ));
    EXPECT_EQ(err->win32, ERROR_INVALID_STATE);
}

TEST_F(CryptoUtilsTest, AsymmetricCipher_ErrorHandling_KeyNotLoaded) {
    AsymmetricCipher cipher(AsymmetricAlgorithm::RSA_2048);
    
    const std::string plaintext = "test";
    std::vector<uint8_t> ciphertext;
    
    EXPECT_FALSE(cipher.Encrypt(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), ciphertext, RSAPaddingScheme::OAEP_SHA256, err.get()
    ));
    EXPECT_EQ(err->win32, ERROR_INVALID_STATE);
}
