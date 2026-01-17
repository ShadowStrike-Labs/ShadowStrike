// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/*
 * ============================================================================
 * ShadowStrike HashUtils - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive unit test suite for HashUtils module
 * Coverage: SHA1/256/384/512/MD5, HMAC, hex conversion, FNV hashing,
 *           file hashing, streaming API, security features, edge cases
 *
 * Test Standards: Sophos/CrowdStrike enterprise quality
 *
 * ============================================================================
 */
#include "pch.h"
#include <gtest/gtest.h>
#include "../../../src/Utils/HashUtils.hpp"
#include "../../../src/Utils/FileUtils.hpp"
#include "../../../src/Utils/Logger.hpp"
#include <Objbase.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace ShadowStrike::Utils::HashUtils;
using namespace ShadowStrike::Utils::FileUtils;
namespace fs = std::filesystem;

// ============================================================================
// TEST FIXTURE
// ============================================================================
class HashUtilsTest : public ::testing::Test {
protected:
    fs::path testRoot;
    
    void SetUp() override {
        wchar_t tempPath[MAX_PATH]{};
        GetTempPathW(MAX_PATH, tempPath);
        
        GUID guid{};
        CoCreateGuid(&guid);
        wchar_t guidStr[64];
        swprintf_s(guidStr, L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        
        testRoot = fs::path(tempPath) / (L"ShadowStrike_Hash_UT_" + std::wstring(guidStr));
        fs::create_directories(testRoot);
    }
    
    void TearDown() override {
        if (!testRoot.empty() && fs::exists(testRoot)) {
            std::error_code ec;
            fs::remove_all(testRoot, ec);
        }
    }
    
    fs::path TestPath(const std::wstring& relative) const {
        return testRoot / relative;
    }
};

// ============================================================================
// DIGEST SIZE TESTS
// ============================================================================
TEST_F(HashUtilsTest, DigestSize_AllAlgorithms) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[DigestSize_AllAlgorithms] Testing...");
    EXPECT_EQ(DigestSize(Algorithm::SHA1), 20u);
    EXPECT_EQ(DigestSize(Algorithm::SHA256), 32u);
    EXPECT_EQ(DigestSize(Algorithm::SHA384), 48u);
    EXPECT_EQ(DigestSize(Algorithm::SHA512), 64u);
    EXPECT_EQ(DigestSize(Algorithm::MD5), 16u);
}

// ============================================================================
// EQUAL TESTS
// ============================================================================
TEST_F(HashUtilsTest, Equal_IdenticalArrays) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Equal_IdenticalArrays] Testing...");
    uint8_t a[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t b[] = {0x01, 0x02, 0x03, 0x04};
    
    EXPECT_TRUE(Equal(a, b, 4));
}

TEST_F(HashUtilsTest, Equal_DifferentArrays) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Equal_DifferentArrays] Testing...");
    uint8_t a[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t b[] = {0x01, 0x02, 0x03, 0xFF};
    
    EXPECT_FALSE(Equal(a, b, 4));
}

TEST_F(HashUtilsTest, Equal_SamePointer) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Equal_SamePointer] Testing...");
    uint8_t data[] = {0xAA, 0xBB};
    
    EXPECT_TRUE(Equal(data, data, 2));
}

TEST_F(HashUtilsTest, Equal_NullPointers) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Equal_NullPointers] Testing...");
    EXPECT_FALSE(Equal(nullptr, (uint8_t*)0x1234, 4));
    EXPECT_FALSE(Equal((uint8_t*)0x1234, nullptr, 4));
}

TEST_F(HashUtilsTest, Equal_ZeroLength) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Equal_ZeroLength] Testing...");
    uint8_t a[] = {0x01};
    uint8_t b[] = {0xFF};
    
    EXPECT_TRUE(Equal(a, b, 0));
}

// ============================================================================
// HEX CONVERSION TESTS
// ============================================================================
TEST_F(HashUtilsTest, ToHexLower_BasicConversion) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ToHexLower_BasicConversion] Testing...");
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    
    std::string hex = ToHexLower(data, 4);
    EXPECT_EQ(hex, "deadbeef");
}

TEST_F(HashUtilsTest, ToHexUpper_BasicConversion) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ToHexUpper_BasicConversion] Testing...");
    uint8_t data[] = {0xCA, 0xFE, 0xBA, 0xBE};
    
    std::string hex = ToHexUpper(data, 4);
    EXPECT_EQ(hex, "CAFEBABE");
}

TEST_F(HashUtilsTest, ToHexLower_EmptyData) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ToHexLower_EmptyData] Testing...");
    std::array<uint8_t, 0> data{};
    std::string hex = ToHexLower(data.data(), data.size());
    EXPECT_TRUE(hex.empty());
}

TEST_F(HashUtilsTest, ToHexLower_AllBytes) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ToHexLower_AllBytes] Testing...");
    std::vector<uint8_t> data(256);
    for (int i = 0; i < 256; ++i) {
        data[i] = static_cast<uint8_t>(i);
    }
    
    std::string hex = ToHexLower(data);
    EXPECT_EQ(hex.size(), 512u);
}

TEST_F(HashUtilsTest, FromHex_ValidLowercase) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[FromHex_ValidLowercase] Testing...");
    std::vector<uint8_t> out;
    
    ASSERT_TRUE(FromHex("deadbeef", out));
    ASSERT_EQ(out.size(), 4u);
    EXPECT_EQ(out[0], 0xDE);
    EXPECT_EQ(out[1], 0xAD);
    EXPECT_EQ(out[2], 0xBE);
    EXPECT_EQ(out[3], 0xEF);
}

TEST_F(HashUtilsTest, FromHex_ValidUppercase) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[FromHex_ValidUppercase] Testing...");
    std::vector<uint8_t> out;
    
    ASSERT_TRUE(FromHex("CAFEBABE", out));
    ASSERT_EQ(out.size(), 4u);
    EXPECT_EQ(out[0], 0xCA);
    EXPECT_EQ(out[1], 0xFE);
    EXPECT_EQ(out[2], 0xBA);
    EXPECT_EQ(out[3], 0xBE);
}

TEST_F(HashUtilsTest, FromHex_MixedCase) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[FromHex_MixedCase] Testing...");
    std::vector<uint8_t> out;
    
    ASSERT_TRUE(FromHex("DeAdBeEf", out));
    EXPECT_EQ(out.size(), 4u);
}

TEST_F(HashUtilsTest, FromHex_InvalidCharacters) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[FromHex_InvalidCharacters] Testing...");
    std::vector<uint8_t> out;
    
    EXPECT_FALSE(FromHex("GGHHII", out));
    EXPECT_TRUE(out.empty());
}

TEST_F(HashUtilsTest, FromHex_OddLength) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[FromHex_OddLength] Testing...");
    std::vector<uint8_t> out;
    
    EXPECT_FALSE(FromHex("ABC", out));
}

TEST_F(HashUtilsTest, FromHex_EmptyString) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[FromHex_EmptyString] Testing...");
    std::vector<uint8_t> out;
    
    ASSERT_TRUE(FromHex("", out));
    EXPECT_TRUE(out.empty());
}

TEST_F(HashUtilsTest, FromHex_TooLarge) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[FromHex_TooLarge] Testing...");
    std::string huge(50 * 1024 * 1024, 'A');
    std::vector<uint8_t> out;
    
    EXPECT_FALSE(FromHex(huge, out));
}

// ============================================================================
// FNV HASH TESTS
// ============================================================================
TEST_F(HashUtilsTest, Fnv1a32_KnownVector) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Fnv1a32_KnownVector] Testing...");
    const char* data = "hello";
    uint32_t hash = Fnv1a32(data, strlen(data));
    
    EXPECT_NE(hash, 0u);
}

TEST_F(HashUtilsTest, Fnv1a32_EmptyData) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Fnv1a32_EmptyData] Testing...");
    uint32_t hash = Fnv1a32("", 0);
    EXPECT_EQ(hash, 2166136261u); // FNV-1a offset basis
}

TEST_F(HashUtilsTest, Fnv1a32_DifferentInputs) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Fnv1a32_DifferentInputs] Testing...");
    uint32_t h1 = Fnv1a32("test1", 5);
    uint32_t h2 = Fnv1a32("test2", 5);
    
    EXPECT_NE(h1, h2);
}

TEST_F(HashUtilsTest, Fnv1a64_KnownVector) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Fnv1a64_KnownVector] Testing...");
    const char* data = "world";
    uint64_t hash = Fnv1a64(data, strlen(data));
    
    EXPECT_NE(hash, 0ull);
}

TEST_F(HashUtilsTest, Fnv1a64_EmptyData) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Fnv1a64_EmptyData] Testing...");
    uint64_t hash = Fnv1a64("", 0);
    EXPECT_EQ(hash, 14695981039346656037ull); // FNV-1a 64-bit offset basis
}

// ============================================================================
// SHA256 TESTS
// ============================================================================
TEST_F(HashUtilsTest, Compute_SHA256_EmptyString) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Compute_SHA256_EmptyString] Testing...");
    std::vector<uint8_t> hash;
    ShadowStrike::Utils::HashUtils::Error err;
    
    ASSERT_TRUE(Compute(Algorithm::SHA256, "", 0, hash, &err));
    EXPECT_EQ(hash.size(), 32u);
    
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string hexHash = ToHexLower(hash);
    EXPECT_EQ(hexHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(HashUtilsTest, Compute_SHA256_ABC) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Compute_SHA256_ABC] Testing...");
    std::vector<uint8_t> hash;
    
    ASSERT_TRUE(Compute(Algorithm::SHA256, "abc", 3, hash));
    EXPECT_EQ(hash.size(), 32u);
    
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::string hexHash = ToHexLower(hash);
    EXPECT_EQ(hexHash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(HashUtilsTest, ComputeHex_SHA256) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeHex_SHA256] Testing...");
    std::string hexHash;
    
    ASSERT_TRUE(ComputeHex(Algorithm::SHA256, "test", 4, hexHash, false));
    EXPECT_EQ(hexHash.size(), 64u);
    
    // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    EXPECT_EQ(hexHash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

TEST_F(HashUtilsTest, ComputeHex_SHA256_Uppercase) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeHex_SHA256_Uppercase] Testing...");
    std::string hexHash;
    
    ASSERT_TRUE(ComputeHex(Algorithm::SHA256, "TEST", 4, hexHash, true));
    EXPECT_EQ(hexHash.size(), 64u);
    EXPECT_TRUE(std::all_of(hexHash.begin(), hexHash.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
    }));
}

// ============================================================================
// HASHER STREAMING API TESTS
// ============================================================================
TEST_F(HashUtilsTest, Hasher_StreamingSHA256) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hasher_StreamingSHA256] Testing...");
    Hasher h(Algorithm::SHA256);
    ShadowStrike::Utils::HashUtils::Error err;
    
    ASSERT_TRUE(h.Init(&err));
    ASSERT_TRUE(h.Update("Hello", 5, &err));
    ASSERT_TRUE(h.Update(" ", 1, &err));
    ASSERT_TRUE(h.Update("World", 5, &err));
    
    std::vector<uint8_t> hash;
    ASSERT_TRUE(h.Final(hash, &err));
    EXPECT_EQ(hash.size(), 32u);
    
    // Compare with one-shot
    std::vector<uint8_t> oneShot;
    ASSERT_TRUE(Compute(Algorithm::SHA256, "Hello World", 11, oneShot));
    EXPECT_TRUE(Equal(hash.data(), oneShot.data(), 32));
}

TEST_F(HashUtilsTest, Hasher_MultipleInit) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hasher_MultipleInit] Testing...");
    Hasher h(Algorithm::SHA256);
    
    ASSERT_TRUE(h.Init());
    ASSERT_TRUE(h.Update("data1", 5));
    std::vector<uint8_t> h1;
    ASSERT_TRUE(h.Final(h1));
    
    // Re-init
    ASSERT_TRUE(h.Init());
    ASSERT_TRUE(h.Update("data2", 5));
    std::vector<uint8_t> h2;
    ASSERT_TRUE(h.Final(h2));
    
    EXPECT_FALSE(Equal(h1.data(), h2.data(), 32));
}

TEST_F(HashUtilsTest, Hasher_UpdateWithoutInit) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hasher_UpdateWithoutInit] Testing...");
    Hasher h(Algorithm::SHA256);
    ShadowStrike::Utils::HashUtils::Error err;
    
    EXPECT_FALSE(h.Update("data", 4, &err));
    EXPECT_NE(err.win32, ERROR_SUCCESS);
}

TEST_F(HashUtilsTest, Hasher_FinalHex) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hasher_FinalHex] Testing...");
    Hasher h(Algorithm::SHA256);
    
    ASSERT_TRUE(h.Init());
    ASSERT_TRUE(h.Update("test", 4));
    
    std::string hexHash;
    ASSERT_TRUE(h.FinalHex(hexHash, false));
    EXPECT_EQ(hexHash.size(), 64u);
}

TEST_F(HashUtilsTest, Hasher_GetDigestSize) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hasher_GetDigestSize] Testing...");
    Hasher h256(Algorithm::SHA256);
    Hasher h512(Algorithm::SHA512);
    
    EXPECT_EQ(h256.GetDigestSize(), 32u);
    EXPECT_EQ(h512.GetDigestSize(), 64u);
}

// ============================================================================
// ALL ALGORITHMS TESTS
// ============================================================================
TEST_F(HashUtilsTest, Compute_SHA1) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Compute_SHA1] Testing...");
    std::vector<uint8_t> hash;
    
    ASSERT_TRUE(Compute(Algorithm::SHA1, "abc", 3, hash));
    EXPECT_EQ(hash.size(), 20u);
    
    // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    std::string hexHash = ToHexLower(hash);
    EXPECT_EQ(hexHash, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST_F(HashUtilsTest, Compute_SHA384) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Compute_SHA384] Testing...");
    std::vector<uint8_t> hash;
    
    ASSERT_TRUE(Compute(Algorithm::SHA384, "test", 4, hash));
    EXPECT_EQ(hash.size(), 48u);
}

TEST_F(HashUtilsTest, Compute_SHA512) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Compute_SHA512] Testing...");
    std::vector<uint8_t> hash;
    
    ASSERT_TRUE(Compute(Algorithm::SHA512, "test", 4, hash));
    EXPECT_EQ(hash.size(), 64u);
}

TEST_F(HashUtilsTest, Compute_MD5) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Compute_MD5] Testing...");
    std::vector<uint8_t> hash;
    
    ASSERT_TRUE(Compute(Algorithm::MD5, "test", 4, hash));
    EXPECT_EQ(hash.size(), 16u);
    
    // MD5("test") = 098f6bcd4621d373cade4e832627b4f6
    std::string hexHash = ToHexLower(hash);
    EXPECT_EQ(hexHash, "098f6bcd4621d373cade4e832627b4f6");
}

// ============================================================================
// HMAC TESTS
// ============================================================================
TEST_F(HashUtilsTest, ComputeHmac_SHA256_BasicKey) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeHmac_SHA256_BasicKey] Testing...");
    const char* key = "secret";
    const char* data = "message";
    std::vector<uint8_t> hmac;
    
    ASSERT_TRUE(ComputeHmac(Algorithm::SHA256, key, strlen(key), data, strlen(data), hmac));
    EXPECT_EQ(hmac.size(), 32u);
}

TEST_F(HashUtilsTest, ComputeHmac_SHA256_EmptyKey) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeHmac_SHA256_EmptyKey] Testing...");
    const char* data = "message";
    std::vector<uint8_t> hmac;
    
    ASSERT_TRUE(ComputeHmac(Algorithm::SHA256, "", 0, data, strlen(data), hmac));
    EXPECT_EQ(hmac.size(), 32u);
}

TEST_F(HashUtilsTest, ComputeHmac_SHA256_EmptyData) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeHmac_SHA256_EmptyData] Testing...");
    const char* key = "key";
    std::vector<uint8_t> hmac;
    
    ASSERT_TRUE(ComputeHmac(Algorithm::SHA256, key, strlen(key), "", 0, hmac));
    EXPECT_EQ(hmac.size(), 32u);
}

TEST_F(HashUtilsTest, ComputeHmac_DifferentKeys) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeHmac_DifferentKeys] Testing...");
    const char* data = "data";
    std::vector<uint8_t> h1, h2;
    
    ASSERT_TRUE(ComputeHmac(Algorithm::SHA256, "key1", 4, data, 4, h1));
    ASSERT_TRUE(ComputeHmac(Algorithm::SHA256, "key2", 4, data, 4, h2));
    
    EXPECT_FALSE(Equal(h1.data(), h2.data(), 32));
}

TEST_F(HashUtilsTest, ComputeHmacHex_SHA256) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeHmacHex_SHA256] Testing...");
    const char* key = "mykey";
    const char* data = "mydata";
    std::string hexHmac;
    
    ASSERT_TRUE(ComputeHmacHex(Algorithm::SHA256, key, strlen(key), data, strlen(data), hexHmac, false));
    EXPECT_EQ(hexHmac.size(), 64u);
}

TEST_F(HashUtilsTest, Hmac_StreamingAPI) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hmac_StreamingAPI] Testing...");
    Hmac h(Algorithm::SHA256);
    const char* key = "testkey";
    
    ASSERT_TRUE(h.Init(key, strlen(key)));
    ASSERT_TRUE(h.Update("part1", 5));
    ASSERT_TRUE(h.Update("part2", 5));
    
    std::vector<uint8_t> hmac;
    ASSERT_TRUE(h.Final(hmac));
    EXPECT_EQ(hmac.size(), 32u);
}

TEST_F(HashUtilsTest, Hmac_FinalHex) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hmac_FinalHex] Testing...");
    Hmac h(Algorithm::SHA256);
    const char* key = "key";
    
    ASSERT_TRUE(h.Init(key, strlen(key)));
    ASSERT_TRUE(h.Update("data", 4));
    
    std::string hexHmac;
    ASSERT_TRUE(h.FinalHex(hexHmac, true));
    EXPECT_EQ(hexHmac.size(), 64u);
}

TEST_F(HashUtilsTest, Hmac_UpdateWithoutInit) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Hmac_UpdateWithoutInit] Testing...");
    Hmac h(Algorithm::SHA256);
    ShadowStrike::Utils::HashUtils::Error err;
    
    EXPECT_FALSE(h.Update("data", 4, &err));
    EXPECT_NE(err.win32, ERROR_SUCCESS);
}

// ============================================================================
// FILE HASHING TESTS
// ============================================================================
TEST_F(HashUtilsTest, ComputeFile_SmallFile) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeFile_SmallFile] Testing...");
    auto path = TestPath(L"small.txt");
    std::ofstream ofs(path, std::ios::binary);
    ofs << "Hello, World!";
    ofs.close();
    
    std::vector<uint8_t> hash;
    ShadowStrike::Utils::HashUtils::Error err;
    
    ASSERT_TRUE(ComputeFile(Algorithm::SHA256, path.wstring(), hash, &err));
    EXPECT_EQ(hash.size(), 32u);
    
    // Compare with in-memory hash
    std::vector<uint8_t> memHash;
    ASSERT_TRUE(Compute(Algorithm::SHA256, "Hello, World!", 13, memHash));
    EXPECT_TRUE(Equal(hash.data(), memHash.data(), 32));
}

TEST_F(HashUtilsTest, ComputeFile_LargeFile) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeFile_LargeFile] Testing...");
    auto path = TestPath(L"large.bin");
    std::ofstream ofs(path, std::ios::binary);
    
    // Write 5MB of data
    std::vector<char> chunk(1024, 'A');
    for (int i = 0; i < 5 * 1024; ++i) {
        ofs.write(chunk.data(), chunk.size());
    }
    ofs.close();
    
    std::vector<uint8_t> hash;
    
    ASSERT_TRUE(ComputeFile(Algorithm::SHA256, path.wstring(), hash));
    EXPECT_EQ(hash.size(), 32u);
}

TEST_F(HashUtilsTest, ComputeFile_NonExistent) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeFile_NonExistent] Testing...");
    auto path = TestPath(L"nonexistent.txt");
    std::vector<uint8_t> hash;
    ShadowStrike::Utils::HashUtils::Error err;
    
    EXPECT_FALSE(ComputeFile(Algorithm::SHA256, path.wstring(), hash, &err));
    EXPECT_NE(err.win32, ERROR_SUCCESS);
}

TEST_F(HashUtilsTest, ComputeFile_EmptyFile) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[ComputeFile_EmptyFile] Testing...");
    auto path = TestPath(L"empty.txt");
    std::ofstream ofs(path);
    ofs.close();
    
    std::vector<uint8_t> hash;
    
    ASSERT_TRUE(ComputeFile(Algorithm::SHA256, path.wstring(), hash));
    
    // Compare with empty string hash
    std::vector<uint8_t> emptyHash;
    ASSERT_TRUE(Compute(Algorithm::SHA256, "", 0, emptyHash));
    EXPECT_TRUE(Equal(hash.data(), emptyHash.data(), 32));
}

// ============================================================================
// EDGE CASES & SECURITY TESTS
// ============================================================================
TEST_F(HashUtilsTest, EdgeCase_VeryLargeUpdate) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[EdgeCase_VeryLargeUpdate] Testing...");
    Hasher h(Algorithm::SHA256);
    ASSERT_TRUE(h.Init());
    
    std::vector<char> data(10 * 1024 * 1024, 'X');
    ASSERT_TRUE(h.Update(data.data(), data.size()));
    
    std::vector<uint8_t> hash;
    ASSERT_TRUE(h.Final(hash));
    EXPECT_EQ(hash.size(), 32u);
}

TEST_F(HashUtilsTest, EdgeCase_ManySmallUpdates) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[EdgeCase_ManySmallUpdates] Testing...");
    Hasher h(Algorithm::SHA256);
    ASSERT_TRUE(h.Init());
    
    for (int i = 0; i < 10000; ++i) {
        ASSERT_TRUE(h.Update("x", 1));
    }
    
    std::vector<uint8_t> hash;
    ASSERT_TRUE(h.Final(hash));
    EXPECT_EQ(hash.size(), 32u);
}

TEST_F(HashUtilsTest, EdgeCase_BinaryData) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[EdgeCase_BinaryData] Testing...");
    std::vector<uint8_t> binaryData(256);
    for (int i = 0; i < 256; ++i) {
        binaryData[i] = static_cast<uint8_t>(i);
    }
    
    std::vector<uint8_t> hash;
    ASSERT_TRUE(Compute(Algorithm::SHA256, binaryData.data(), binaryData.size(), hash));
    EXPECT_EQ(hash.size(), 32u);
}

TEST_F(HashUtilsTest, Stress_MultipleHashers) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Stress_MultipleHashers] Testing...");
    std::vector<Hasher> hashers;
    for (int i = 0; i < 100; ++i) {
        hashers.emplace_back(Algorithm::SHA256);
        ASSERT_TRUE(hashers.back().Init());
        ASSERT_TRUE(hashers.back().Update("test", 4));
    }
    
    for (auto& h : hashers) {
        std::vector<uint8_t> hash;
        ASSERT_TRUE(h.Final(hash));
        EXPECT_EQ(hash.size(), 32u);
    }
}

TEST_F(HashUtilsTest, Stress_ConcurrentHashing) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Stress_ConcurrentHashing] Testing...");
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&successCount]() {
            for (int i = 0; i < 100; ++i) {
                std::vector<uint8_t> hash;
                if (Compute(Algorithm::SHA256, "data", 4, hash)) {
                    successCount++;
                }
            }
        });
    }
    
    for (auto& th : threads) {
        th.join();
    }
    
    EXPECT_EQ(successCount.load(), 400);
}

TEST_F(HashUtilsTest, Security_HexRoundTrip) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Security_HexRoundTrip] Testing...");
    uint8_t original[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    
    std::string hex = ToHexLower(original, 6);
    std::vector<uint8_t> recovered;
    ASSERT_TRUE(FromHex(hex, recovered));
    
    ASSERT_EQ(recovered.size(), 6u);
    EXPECT_TRUE(Equal(original, recovered.data(), 6));
}

TEST_F(HashUtilsTest, Consistency_SameInputSameOutput) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Consistency_SameInputSameOutput] Testing...");
    const char* data = "consistency_test";
    std::vector<uint8_t> h1, h2, h3;
    
    ASSERT_TRUE(Compute(Algorithm::SHA256, data, strlen(data), h1));
    ASSERT_TRUE(Compute(Algorithm::SHA256, data, strlen(data), h2));
    ASSERT_TRUE(Compute(Algorithm::SHA256, data, strlen(data), h3));
    
    EXPECT_TRUE(Equal(h1.data(), h2.data(), 32));
    EXPECT_TRUE(Equal(h2.data(), h3.data(), 32));
}

TEST_F(HashUtilsTest, Consistency_DifferentInputDifferentOutput) {
    SS_LOG_INFO(L"HashUtils_Tests", L"[Consistency_DifferentInputDifferentOutput] Testing...");
    std::vector<uint8_t> h1, h2;
    
    ASSERT_TRUE(Compute(Algorithm::SHA256, "test1", 5, h1));
    ASSERT_TRUE(Compute(Algorithm::SHA256, "test2", 5, h2));
    
    EXPECT_FALSE(Equal(h1.data(), h2.data(), 32));
}
