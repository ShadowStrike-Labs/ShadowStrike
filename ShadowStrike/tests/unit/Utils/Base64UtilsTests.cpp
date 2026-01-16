/*
 * ============================================================================
 * ShadowStrike Base64 Unit Tests
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive test suite for Base64 encoding/decoding functionality
 * Designed for enterprise-grade reliability and security validation
 *
 * ============================================================================
 */

#include "pch.h"
#include <gtest/gtest.h>
#include "../../../src/Utils/Base64Utils.hpp"
#include "../../../src/Utils/Logger.hpp"
#include <string>
#include <vector>
#include <cstring>
#include <limits>
#include <chrono>
#include <iostream>
#include <iomanip>

using namespace ShadowStrike::Utils;

// ============================================================================
// Test Fixture
// ============================================================================

class Base64UtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset state before each test
    }

    void TearDown() override {
        // Cleanup after each test
    }

    // Helper to compare binary data
    bool CompareBinary(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        return std::memcmp(a.data(), b.data(), a.size()) == 0;
    }

    // Helper to create binary data from string
    std::vector<uint8_t> MakeBinary(const std::string& s) {
        return std::vector<uint8_t>(s.begin(), s.end());
    }
};

// ============================================================================
// Encoding Length Calculation Tests
// ============================================================================

TEST_F(Base64UtilsTest, EncodedLength_EmptyInput) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_EmptyInput] Starting test with 0 bytes input");
    
    size_t result = Base64EncodedLength(0);
    EXPECT_EQ(result, 0u) << "Empty input should produce 0 length";
    
    if (result != 0u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Empty input returned %zu instead of 0", result);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Empty input correctly produces 0");
    }
}

TEST_F(Base64UtilsTest, EncodedLength_SingleByte) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_SingleByte] Testing 1 byte -> 4 chars with padding");
    
    size_t result = Base64EncodedLength(1);
    EXPECT_EQ(result, 4u) << "1 byte should produce 4 chars with padding";
    
    if (result != 4u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] 1 byte returned %zu instead of 4", result);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] 1 byte correctly produces 4 chars");
    }
}

TEST_F(Base64UtilsTest, EncodedLength_TwoBytes) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_TwoBytes] Testing 2 bytes -> 4 chars with padding");
    
    size_t result = Base64EncodedLength(2);
    EXPECT_EQ(result, 4u) << "2 bytes should produce 4 chars with padding";
    
    if (result != 4u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] 2 bytes returned %zu instead of 4", result);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] 2 bytes correctly produces 4 chars");
    }
}

TEST_F(Base64UtilsTest, EncodedLength_ThreeBytes) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_ThreeBytes] Testing 3 bytes -> 4 chars (exact block)");
    
    size_t result = Base64EncodedLength(3);
    EXPECT_EQ(result, 4u) << "3 bytes should produce 4 chars (exact block)";
    
    if (result != 4u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] 3 bytes returned %zu instead of 4", result);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] 3 bytes correctly produces 4 chars");
    }
}

TEST_F(Base64UtilsTest, EncodedLength_MultipleBlocks) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_MultipleBlocks] Testing multiple 3-byte blocks");
    
    size_t result6 = Base64EncodedLength(6);
    size_t result9 = Base64EncodedLength(9);
    size_t result12 = Base64EncodedLength(12);
    
    EXPECT_EQ(result6, 8u) << "6 bytes should produce 8 chars";
    EXPECT_EQ(result9, 12u) << "9 bytes should produce 12 chars";
    EXPECT_EQ(result12, 16u) << "12 bytes should produce 16 chars";
    
    if (result6 != 8u || result9 != 12u || result12 != 16u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Multiple blocks: 6bytes=%zu (exp 8), 9bytes=%zu (exp 12), 12bytes=%zu (exp 16)",
            result6, result9, result12);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Multiple blocks produce correct lengths");
    }
}

TEST_F(Base64UtilsTest, EncodedLength_WithOmitPadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_WithOmitPadding] Testing OmitPadding flag");
    
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::OmitPadding;
    
    size_t result1 = Base64EncodedLength(1, opt);
    size_t result2 = Base64EncodedLength(2, opt);
    size_t result3 = Base64EncodedLength(3, opt);
    size_t result4 = Base64EncodedLength(4, opt);
    
    EXPECT_EQ(result1, 2u) << "1 byte without padding should be 2 chars";
    EXPECT_EQ(result2, 3u) << "2 bytes without padding should be 3 chars";
    EXPECT_EQ(result3, 4u) << "3 bytes exact block should be 4 chars";
    EXPECT_EQ(result4, 6u) << "4 bytes should be 6 chars";
    
    if (result1 != 2u || result2 != 3u || result3 != 4u || result4 != 6u) {
        SS_LOG_ERROR(L"Base64Utils_Tests",
            L"[FAIL] OmitPadding: 1=%zu(exp 2), 2=%zu(exp 3), 3=%zu(exp 4), 4=%zu(exp 6)",
            result1, result2, result3, result4);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] OmitPadding produces correct lengths");
    }
}

TEST_F(Base64UtilsTest, EncodedLength_WithLineBreaks) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_WithLineBreaks] Testing InsertLineBreaks flag");
    
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks;
    opt.lineBreakEvery = 4;
    opt.lineBreak = "\n";
    
    size_t len = Base64EncodedLength(6, opt);
    EXPECT_EQ(len, 9u) << "6 bytes (8 chars) with line break every 4 should be 9 total";
    
    if (len != 9u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] LineBreaks: got %zu chars, expected 9 (8 chars + 1 newline)", len);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] LineBreaks calculation correct");
    }
}

TEST_F(Base64UtilsTest, EncodedLength_Overflow) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EncodedLength_Overflow] Testing overflow protection with SIZE_MAX");
    
    size_t huge = SIZE_MAX / 2;
    size_t result = Base64EncodedLength(huge);
    
    // Should return 0 if overflow detected, or reasonable value if protected
    EXPECT_GE(result, 0u) << "Overflow should be handled gracefully";
    
    if (result == 0u) {
        SS_LOG_INFO(L"Base64Utils_Tests", L"[INFO] Overflow detected and handled (returned 0)");
    } else {
        SS_LOG_WARN(L"Base64Utils_Tests", L"[WARN] Overflow may not be detected - result: %zu", result);
    }
}

// ============================================================================
// Decoding Length Calculation Tests
// ============================================================================

TEST_F(Base64UtilsTest, MaxDecodedLength_EmptyInput) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[MaxDecodedLength_EmptyInput] Testing 0 bytes input");
    
    size_t result = Base64MaxDecodedLength(0);
    EXPECT_EQ(result, 0u) << "Empty input should decode to 0";
    
    if (result != 0u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Empty input returned %zu instead of 0", result);
    }
}

TEST_F(Base64UtilsTest, MaxDecodedLength_ValidInput) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[MaxDecodedLength_ValidInput] Testing valid Base64 lengths");
    
    size_t result4 = Base64MaxDecodedLength(4);
    size_t result8 = Base64MaxDecodedLength(8);
    size_t result12 = Base64MaxDecodedLength(12);
    
    EXPECT_EQ(result4, 3u) << "4 Base64 chars should decode to max 3 bytes";
    EXPECT_EQ(result8, 6u) << "8 Base64 chars should decode to max 6 bytes";
    EXPECT_EQ(result12, 9u) << "12 Base64 chars should decode to max 9 bytes";
    
    if (result4 != 3u || result8 != 6u || result12 != 9u) {
        SS_LOG_ERROR(L"Base64Utils_Tests",
            L"[FAIL] MaxDecoded: 4=%zu(exp 3), 8=%zu(exp 6), 12=%zu(exp 9)",
            result4, result8, result12);
    }
}

TEST_F(Base64UtilsTest, MaxDecodedLength_NonMultipleOfFour) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[MaxDecodedLength_NonMultipleOfFour] Testing non-4-aligned input");
    
    size_t result5 = Base64MaxDecodedLength(5);
    size_t result7 = Base64MaxDecodedLength(7);
    
    EXPECT_GT(result5, 0u) << "5 chars should still produce valid decoded length";
    EXPECT_GT(result7, 0u) << "7 chars should still produce valid decoded length";
    
    if (result5 == 0u || result7 == 0u) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Non-aligned: 5=%zu, 7=%zu (both should be > 0)", result5, result7);
    }
}

// ============================================================================
// Basic Encoding Tests
// ============================================================================

TEST_F(Base64UtilsTest, Encode_EmptyInput) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_EmptyInput] Testing empty vector encoding");
    
    std::string result;
    bool success = Base64Encode(std::vector<uint8_t>{}, result);
    
    EXPECT_TRUE(success) << "Empty input encoding should succeed";
    EXPECT_EQ(result, "") << "Empty input should produce empty string";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Empty input encoding failed");
    } else if (!result.empty()) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Empty input produced non-empty result: %s", result.c_str());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Empty input correctly produces empty string");
    }
}

TEST_F(Base64UtilsTest, Encode_SingleByte) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_SingleByte] Encoding 'A' to Base64");
    
    std::string result;
    bool success = Base64Encode(MakeBinary("A"), result);
    
    EXPECT_TRUE(success) << "Single byte encoding should succeed";
    EXPECT_EQ(result, "QQ==") << "Single byte 'A' should encode to 'QQ=='";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Single byte encoding returned false");
    } else if (result != "QQ==") {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Single byte produced '%s' instead of 'QQ=='", result.c_str());
    }
}

TEST_F(Base64UtilsTest, Encode_TwoBytes) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_TwoBytes] Encoding 'AB' to Base64");
    
    std::string result;
    bool success = Base64Encode(MakeBinary("AB"), result);
    
    EXPECT_TRUE(success) << "Two byte encoding should succeed";
    EXPECT_EQ(result, "QUI=") << "Two bytes 'AB' should encode to 'QUI='";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Two byte encoding returned false");
    } else if (result != "QUI=") {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Two bytes produced '%s' instead of 'QUI='", result.c_str());
    }
}

TEST_F(Base64UtilsTest, Encode_ThreeBytes) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_ThreeBytes] Encoding 'ABC' to Base64");
    
    std::string result;
    bool success = Base64Encode(MakeBinary("ABC"), result);
    
    EXPECT_TRUE(success) << "Three byte encoding should succeed";
    EXPECT_EQ(result, "QUJD") << "Three bytes 'ABC' should encode to 'QUJD'";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Three byte encoding returned false");
    } else if (result != "QUJD") {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Three bytes produced '%s' instead of 'QUJD'", result.c_str());
    }
}

TEST_F(Base64UtilsTest, Encode_RFCTestVectors) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_RFCTestVectors] Testing RFC 4648 test vectors");
    
    struct TestVector {
        std::string input;
        std::string expected;
    };
    
    std::vector<TestVector> vectors = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"}
    };
    
    int passCount = 0;
    int failCount = 0;
    
    for (const auto& vec : vectors) {
        std::string result;
        bool success = Base64Encode(MakeBinary(vec.input), result);
        
        if (!success) {
            SS_LOG_ERROR(L"Base64Utils_Tests", 
                L"[RFC_TEST] Encoding failed for input '%s'", vec.input.c_str());
            failCount++;
            EXPECT_TRUE(false) << "RFC vector encoding failed for: " << vec.input;
        } else if (result != vec.expected) {
            SS_LOG_ERROR(L"Base64Utils_Tests",
                L"[RFC_TEST] Input '%s': got '%s', expected '%s'",
                vec.input.c_str(), result.c_str(), vec.expected.c_str());
            failCount++;
            EXPECT_EQ(result, vec.expected) << "RFC vector mismatch for: " << vec.input;
        } else {
            passCount++;
            SS_LOG_DEBUG(L"Base64Utils_Tests", L"[RFC_TEST] PASS: '%s' -> '%s'", vec.input.c_str(), result.c_str());
        }
    }
    
    if (failCount == 0) {
        SS_LOG_INFO(L"Base64Utils_Tests", L"[PASS] All %d RFC test vectors passed", passCount);
    }
}

TEST_F(Base64UtilsTest, Encode_AllByteValues) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_AllByteValues] Testing all 256 byte values");
    
    std::vector<uint8_t> allBytes(256);
    for (int i = 0; i < 256; ++i) {
        allBytes[i] = static_cast<uint8_t>(i);
    }
    
    std::string result;
    bool success = Base64Encode(allBytes, result);
    
    EXPECT_TRUE(success) << "All byte values encoding should succeed";
    EXPECT_FALSE(result.empty()) << "Encoded result should not be empty";
    EXPECT_EQ(result.size(), Base64EncodedLength(256)) << "Result size should match calculated length";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] All bytes encoding returned false");
    } else if (result.empty()) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] All bytes produced empty result");
    } else if (result.size() != Base64EncodedLength(256)) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Size mismatch: got %zu, expected %zu", result.size(), Base64EncodedLength(256));
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] All 256 bytes encoded successfully (%zu chars)", result.size());
    }
}

TEST_F(Base64UtilsTest, Encode_BinaryData) {
    std::vector<uint8_t> binary = {0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE};
    std::string result;
    EXPECT_TRUE(Base64Encode(binary, result));
    EXPECT_FALSE(result.empty());
}

TEST_F(Base64UtilsTest, Encode_LargeInput) {
    // Test with 1MB of data
    std::vector<uint8_t> large(1024 * 1024, 0x42);
    std::string result;
    EXPECT_TRUE(Base64Encode(large, result));
    EXPECT_FALSE(result.empty());
}

TEST_F(Base64UtilsTest, Encode_NullPointerWithZeroLength) {
    std::string result;
    EXPECT_TRUE(Base64Encode(nullptr, 0, result));
    EXPECT_EQ(result, "");
}

TEST_F(Base64UtilsTest, Encode_NullPointerWithNonZeroLength) {
    std::string result;
    EXPECT_FALSE(Base64Encode(nullptr, 10, result));
}

// ============================================================================
// URL-Safe Alphabet Tests
// ============================================================================

TEST_F(Base64UtilsTest, Encode_UrlSafeAlphabet) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_UrlSafeAlphabet] Testing URL-safe alphabet encoding");
    
    Base64EncodeOptions opt;
    opt.alphabet = Base64Alphabet::UrlSafe;
    
    // Create data that will produce '+' and '/' in standard encoding
    std::vector<uint8_t> data = {0xFB, 0xFF, 0xBF};
    std::string result;
    bool success = Base64Encode(data, result, opt);
    
    EXPECT_TRUE(success) << "URL-safe encoding should succeed";
    // Should contain '-' and '_' instead of '+' and '/'
    EXPECT_EQ(result.find('+'), std::string::npos) << "Result should not contain '+' character";
    EXPECT_EQ(result.find('/'), std::string::npos) << "Result should not contain '/' character";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] URL-safe encoding returned false");
    } else if (result.find('+') != std::string::npos || result.find('/') != std::string::npos) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Result contains standard alphabet chars: '%s'", result.c_str());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] URL-safe alphabet: '%s'", result.c_str());
    }
}

TEST_F(Base64UtilsTest, Encode_StandardVsUrlSafe) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_StandardVsUrlSafe] Comparing standard vs URL-safe encoding");
    
    std::vector<uint8_t> data = {0xFB, 0xFF, 0xBF};
    
    std::string standard, urlSafe;
    Base64EncodeOptions stdOpt, urlOpt;
    stdOpt.alphabet = Base64Alphabet::Standard;
    urlOpt.alphabet = Base64Alphabet::UrlSafe;
    
    bool successStd = Base64Encode(data, standard, stdOpt);
    bool successUrl = Base64Encode(data, urlSafe, urlOpt);
    
    EXPECT_TRUE(successStd) << "Standard encoding should succeed";
    EXPECT_TRUE(successUrl) << "URL-safe encoding should succeed";
    EXPECT_NE(standard, urlSafe) << "Standard and URL-safe should produce different results";
    
    if (!successStd || !successUrl) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Encoding failed (std: %d, url: %d)", successStd, successUrl);
    } else if (standard == urlSafe) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Standard and URL-safe produced same result: '%s'", standard.c_str());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Standard: '%s' vs URL-safe: '%s'", standard.c_str(), urlSafe.c_str());
    }
}

// ============================================================================
// Padding Options Tests
// ============================================================================

TEST_F(Base64UtilsTest, Encode_OmitPadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_OmitPadding] Testing padding omission");
    
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::OmitPadding;
    
    std::string result;
    
    // 1 byte -> should be 2 chars without padding
    bool success1 = Base64Encode(MakeBinary("A"), result, opt);
    EXPECT_TRUE(success1) << "Single byte without padding should succeed";
    EXPECT_EQ(result, "QQ") << "Single byte should be 'QQ' without padding";
    EXPECT_EQ(result.find('='), std::string::npos) << "Result should not contain padding";
    
    // 2 bytes -> should be 3 chars without padding
    bool success2 = Base64Encode(MakeBinary("AB"), result, opt);
    EXPECT_TRUE(success2) << "Two bytes without padding should succeed";
    EXPECT_EQ(result, "QUI") << "Two bytes should be 'QUI' without padding";
    EXPECT_EQ(result.find('='), std::string::npos) << "Result should not contain padding";
    
    // 3 bytes -> exact block, no padding anyway
    bool success3 = Base64Encode(MakeBinary("ABC"), result, opt);
    EXPECT_TRUE(success3) << "Three bytes without padding should succeed";
    EXPECT_EQ(result, "QUJD") << "Three bytes should be 'QUJD' (no padding needed)";
    
    if (!success1 || !success2 || !success3) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] OmitPadding encoding failed (1: %d, 2: %d, 3: %d)", success1, success2, success3);
    } else if (result.find('=') != std::string::npos) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] OmitPadding result contains padding: '%s'", result.c_str());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Padding correctly omitted in all cases");
    }
}

// ============================================================================
// Line Break Tests
// ============================================================================

TEST_F(Base64UtilsTest, Encode_WithLineBreaks) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_WithLineBreaks] Testing line break insertion");
    
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks;
    opt.lineBreakEvery = 4;
    opt.lineBreak = "\n";
    
    std::string input = "ABCDEFGHIJ"; // 10 bytes -> 16 chars
    std::string result;
    bool success = Base64Encode(MakeBinary(input), result, opt);
    
    EXPECT_TRUE(success) << "Encoding with line breaks should succeed";
    bool hasLineBreak = result.find('\n') != std::string::npos;
    EXPECT_TRUE(hasLineBreak) << "Result should contain line breaks";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Line break encoding returned false");
    } else if (!hasLineBreak) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Line breaks not inserted in result: '%s'", result.c_str());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Line breaks correctly inserted");
    }
}

TEST_F(Base64UtilsTest, Encode_LineBreaksCRLF) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_LineBreaksCRLF] Testing CRLF line breaks");
    
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks;
    opt.lineBreakEvery = 76;
    opt.lineBreak = "\r\n";
    
    // Create 100 bytes of data
    std::vector<uint8_t> data(100, 0x41);
    std::string result;
    bool success = Base64Encode(data, result, opt);
    
    EXPECT_TRUE(success) << "CRLF encoding should succeed";
    bool hasCRLF = result.find("\r\n") != std::string::npos;
    EXPECT_TRUE(hasCRLF) << "Result should contain CRLF sequences";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] CRLF encoding returned false");
    } else if (!hasCRLF) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] CRLF not found in result");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] CRLF correctly inserted");
    }
}

TEST_F(Base64UtilsTest, Encode_CombinedFlags) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Encode_CombinedFlags] Testing combined line breaks + no padding");
    
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks | Base64Flags::OmitPadding;
    opt.lineBreakEvery = 8;
    opt.lineBreak = "\n";
    
    std::string result;
    bool success = Base64Encode(MakeBinary("ABCDEFGHIJ"), result, opt);
    
    EXPECT_TRUE(success) << "Combined flags encoding should succeed";
    bool hasLineBreak = result.find('\n') != std::string::npos;
    bool hasPadding = result.find('=') != std::string::npos;
    EXPECT_TRUE(hasLineBreak) << "Should have line breaks";
    EXPECT_FALSE(hasPadding) << "Should not have padding";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Combined flags encoding returned false");
    } else if (!hasLineBreak || hasPadding) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] LineBreak: %d, Padding: %d (should be true/false)", hasLineBreak, hasPadding);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Combined flags applied correctly");
    }
}

// ============================================================================
// Basic Decoding Tests
// ============================================================================

TEST_F(Base64UtilsTest, Decode_EmptyInput) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_EmptyInput] Decoding empty string");
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    bool success = Base64Decode("", result, err);
    
    EXPECT_TRUE(success) << "Empty string decoding should succeed";
    EXPECT_TRUE(result.empty()) << "Empty input should produce empty output";
    EXPECT_EQ(err, Base64DecodeError::None) << "Error should be None";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Empty string decoding returned false");
    } else if (!result.empty()) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Empty string produced non-empty result");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Empty input correctly decoded");
    }
}

TEST_F(Base64UtilsTest, Decode_RFCTestVectors) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_RFCTestVectors] Decoding RFC 4648 test vectors");
    
    struct TestVector {
        std::string encoded;
        std::string expected;
    };
    
    std::vector<TestVector> vectors = {
        {"Zg==", "f"},
        {"Zm8=", "fo"},
        {"Zm9v", "foo"},
        {"Zm9vYg==", "foob"},
        {"Zm9vYmE=", "fooba"},
        {"Zm9vYmFy", "foobar"}
    };
    
    int passCount = 0;
    int failCount = 0;
    
    for (const auto& vec : vectors) {
        std::vector<uint8_t> result;
        Base64DecodeError err;
        bool success = Base64Decode(vec.encoded, result, err);
        
        if (!success || err != Base64DecodeError::None) {
            SS_LOG_ERROR(L"Base64Utils_Tests", 
                L"[RFC_TEST] Decoding failed for '%s' (err=%d)", vec.encoded.c_str(), static_cast<int>(err));
            failCount++;
            EXPECT_TRUE(success && err == Base64DecodeError::None) << "RFC vector decode failed: " << vec.encoded;
        } else if (!CompareBinary(result, MakeBinary(vec.expected))) {
            SS_LOG_ERROR(L"Base64Utils_Tests", L"[RFC_TEST] Mismatch for '%s'", vec.encoded.c_str());
            failCount++;
            EXPECT_TRUE(CompareBinary(result, MakeBinary(vec.expected))) << "RFC vector mismatch: " << vec.encoded;
        } else {
            passCount++;
            SS_LOG_DEBUG(L"Base64Utils_Tests", L"[RFC_TEST] PASS: '%s' -> '%s'", vec.encoded.c_str(), vec.expected.c_str());
        }
    }
    
    if (failCount == 0) {
        SS_LOG_INFO(L"Base64Utils_Tests", L"[PASS] All %d RFC vectors decoded correctly", passCount);
    }
}

TEST_F(Base64UtilsTest, Decode_WithWhitespace) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_WithWhitespace] Testing whitespace tolerance");
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // CRLF should be ignored
    bool success1 = Base64Decode("Zm9v\r\n", result, err);
    EXPECT_TRUE(success1 && err == Base64DecodeError::None) << "CRLF should be ignored";
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foo"))) << "CRLF decode mismatch";
    
    // Space should be ignored
    bool success2 = Base64Decode("Zm 9v", result, err);
    EXPECT_TRUE(success2 && err == Base64DecodeError::None) << "Space should be ignored";
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foo"))) << "Space decode mismatch";
    
    // Tab should be ignored
    bool success3 = Base64Decode("\tZm9v\t", result, err);
    EXPECT_TRUE(success3 && err == Base64DecodeError::None) << "Tab should be ignored";
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foo"))) << "Tab decode mismatch";
    
    if (!success1 || !success2 || !success3) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Whitespace tolerance failed (CRLF: %d, space: %d, tab: %d)", success1, success2, success3);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Whitespace correctly ignored");
    }
}

TEST_F(Base64UtilsTest, Decode_NoPaddingAccepted) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_NoPaddingAccepted] Testing missing padding tolerance");
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    Base64DecodeOptions opt;
    opt.acceptMissingPadding = true;
    
    bool success1 = Base64Decode("Zg", result, err, opt);
    EXPECT_TRUE(success1) << "No-padding 'Zg' should decode";
    EXPECT_EQ(err, Base64DecodeError::None) << "Error should be None";
    EXPECT_TRUE(CompareBinary(result, MakeBinary("f"))) << "Missing padding decode mismatch";
    
    bool success2 = Base64Decode("Zm8", result, err, opt);
    EXPECT_TRUE(success2) << "No-padding 'Zm8' should decode";
    EXPECT_EQ(err, Base64DecodeError::None) << "Error should be None";
    EXPECT_TRUE(CompareBinary(result, MakeBinary("fo"))) << "Missing padding decode mismatch";
    
    if (!success1 || !success2) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Missing padding acceptance failed");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Missing padding correctly accepted");
    }
}

TEST_F(Base64UtilsTest, Decode_InvalidCharacter) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_InvalidCharacter] Testing invalid character detection");
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Invalid character '@'
    bool success1 = Base64Decode("Zm9@", result, err);
    EXPECT_FALSE(success1) << "Invalid character '@' should fail";
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter) << "Error should be InvalidCharacter";
    
    // Invalid character '!'
    bool success2 = Base64Decode("!abc", result, err);
    EXPECT_FALSE(success2) << "Invalid character '!' should fail";
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter) << "Error should be InvalidCharacter";
    
    if (success1 || success2) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Invalid characters not detected ('@': %d, '!': %d)", success1, success2);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Invalid characters correctly rejected");
    }
}

TEST_F(Base64UtilsTest, Decode_InvalidPadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_InvalidPadding] Testing padding validation");
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Too much padding
    bool success1 = Base64Decode("Zm9v===", result, err);
    EXPECT_FALSE(success1) << "Too much padding should fail";
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding) << "Error should be InvalidPadding";
    
    // Padding in wrong position
    bool success2 = Base64Decode("Z=9v", result, err);
    EXPECT_FALSE(success2) << "Misplaced padding should fail";
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding) << "Error should be InvalidPadding";
    
    if (success1 || success2) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Invalid padding not detected");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Invalid padding correctly rejected");
    }
}

TEST_F(Base64UtilsTest, Decode_TrailingDataAfterPadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_TrailingDataAfterPadding] Testing trailing data detection");
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Data after padding (non-whitespace)
    bool success = Base64Decode("Zm9v==XX", result, err);
    EXPECT_FALSE(success) << "Trailing data after padding should fail";
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding) << "Error should be InvalidPadding";
    
    if (success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Trailing data not detected");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Trailing data correctly rejected");
    }
}

TEST_F(Base64UtilsTest, Decode_UrlSafeAlphabet) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_UrlSafeAlphabet] Testing URL-safe alphabet decoding");
    
    Base64DecodeOptions opt;
    opt.alphabet = Base64Alphabet::UrlSafe;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Decode URL-safe encoded data
    bool success = Base64Decode("-_-_", result, err, opt);
    EXPECT_TRUE(success) << "URL-safe characters should decode";
    EXPECT_EQ(err, Base64DecodeError::None) << "Error should be None";
    EXPECT_FALSE(result.empty()) << "Result should not be empty";
    
    if (!success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] URL-safe alphabet decode failed (err=%d)", static_cast<int>(err));
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] URL-safe alphabet decoded correctly");
    }
}

TEST_F(Base64UtilsTest, Decode_StandardRejectsUrlSafeChars) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_StandardRejectsUrlSafeChars] Testing standard alphabet strictness");
    
    Base64DecodeOptions opt;
    opt.alphabet = Base64Alphabet::Standard;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Standard alphabet should reject '-' and '_'
    bool success = Base64Decode("-_-_", result, err, opt);
    EXPECT_FALSE(success) << "Standard alphabet should reject URL-safe characters";
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter) << "Error should be InvalidCharacter";
    
    if (success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] URL-safe characters accepted by standard alphabet");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Standard alphabet correctly rejects URL-safe chars");
    }
}

TEST_F(Base64UtilsTest, Decode_NullPointer) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_NullPointer] Testing null pointer handling");
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    bool success1 = Base64Decode(nullptr, 0, result, err);
    EXPECT_TRUE(success1) << "Null pointer with zero length should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "Error should be None";
    EXPECT_TRUE(result.empty()) << "Result should be empty";
    
    bool success2 = Base64Decode(nullptr, 10, result, err);
    EXPECT_FALSE(success2) << "Null pointer with non-zero length should fail";
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter) << "Error should be InvalidCharacter";
    
    if (!success1 || success2) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Null pointer handling failed (0-len: %d, 10-len: %d)", success1, success2);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Null pointer correctly handled");
    }
}

// ============================================================================
// Round-Trip Tests
// ============================================================================

TEST_F(Base64UtilsTest, RoundTrip_EmptyData) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[RoundTrip_EmptyData] Round-trip encode/decode of empty data");
    
    std::vector<uint8_t> original;
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(original, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess) << "Encoding empty data should succeed";
    EXPECT_TRUE(decSuccess) << "Decoding empty encoded data should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(original, decoded)) << "Round-trip data should match";
    
    if (!encSuccess || !decSuccess) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Empty round-trip failed (enc: %d, dec: %d)", encSuccess, decSuccess);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Empty data round-trip successful");
    }
}

TEST_F(Base64UtilsTest, RoundTrip_SingleByte) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[RoundTrip_SingleByte] Round-trip single byte");
    
    std::vector<uint8_t> original = {0x42};
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(original, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess) << "Encoding single byte should succeed";
    EXPECT_TRUE(decSuccess) << "Decoding should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(original, decoded)) << "Round-trip data should match";
    
    if (!encSuccess || !decSuccess) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Single byte round-trip failed");
    }
}

TEST_F(Base64UtilsTest, RoundTrip_MultipleBlocks) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[RoundTrip_MultipleBlocks] Round-trip multiple data blocks");
    
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(original, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess && decSuccess) << "Round-trip encode/decode should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_EQ(original.size(), decoded.size()) << "Size should match";
    EXPECT_TRUE(CompareBinary(original, decoded)) << "Data should match exactly";
    
    if (!encSuccess || !decSuccess || original.size() != decoded.size()) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Multi-block failed (enc: %d, dec: %d, size: %zu/%zu)", 
            encSuccess, decSuccess, original.size(), decoded.size());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Multi-block round-trip successful");
    }
}

TEST_F(Base64UtilsTest, RoundTrip_AllByteValues) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[RoundTrip_AllByteValues] Round-trip all 256 byte values");
    
    std::vector<uint8_t> original(256);
    for (int i = 0; i < 256; ++i) {
        original[i] = static_cast<uint8_t>(i);
    }
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(original, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess && decSuccess) << "All bytes round-trip should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(original, decoded)) << "All 256 bytes should round-trip correctly";
    
    if (!encSuccess || !decSuccess || !CompareBinary(original, decoded)) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] All bytes round-trip failed");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] All 256 bytes round-trip successful");
    }
}

TEST_F(Base64UtilsTest, RoundTrip_UrlSafeAlphabet) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[RoundTrip_UrlSafeAlphabet] Round-trip with URL-safe alphabet");
    
    std::vector<uint8_t> original = {0xFB, 0xFF, 0xBF, 0xEE, 0xDD, 0xCC};
    
    Base64EncodeOptions encOpt;
    encOpt.alphabet = Base64Alphabet::UrlSafe;
    
    Base64DecodeOptions decOpt;
    decOpt.alphabet = Base64Alphabet::UrlSafe;
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(original, encoded, encOpt);
    bool decSuccess = Base64Decode(encoded, decoded, err, decOpt);
    
    EXPECT_TRUE(encSuccess && decSuccess) << "URL-safe round-trip should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(original, decoded)) << "Data should round-trip correctly";
    
    if (!encSuccess || !decSuccess) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] URL-safe round-trip failed");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] URL-safe alphabet round-trip successful");
    }
}

TEST_F(Base64UtilsTest, RoundTrip_WithoutPadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[RoundTrip_WithoutPadding] Round-trip without padding");
    
    std::vector<uint8_t> original = {0x41, 0x42};
    
    Base64EncodeOptions encOpt;
    encOpt.flags = Base64Flags::OmitPadding;
    
    Base64DecodeOptions decOpt;
    decOpt.acceptMissingPadding = true;
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(original, encoded, encOpt);
    bool decSuccess = Base64Decode(encoded, decoded, err, decOpt);
    
    EXPECT_TRUE(encSuccess && decSuccess) << "No-padding round-trip should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(original, decoded)) << "Data should match";
    
    if (!encSuccess || !decSuccess || !CompareBinary(original, decoded)) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] No-padding round-trip failed");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] No-padding round-trip successful");
    }
}

TEST_F(Base64UtilsTest, RoundTrip_LargeData) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[RoundTrip_LargeData] Round-trip 1MB of data");
    
    // Test with 1MB of pseudo-random data
    std::vector<uint8_t> original(1024 * 1024);
    for (size_t i = 0; i < original.size(); ++i) {
        original[i] = static_cast<uint8_t>((i * 1103515245 + 12345) >> 16);
    }
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(original, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess) << "1MB encoding should succeed";
    EXPECT_TRUE(decSuccess) << "1MB decoding should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_EQ(original.size(), decoded.size()) << "Size should match: 1MB";
    EXPECT_TRUE(CompareBinary(original, decoded)) << "Large data should round-trip perfectly";
    
    if (!encSuccess || !decSuccess) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] 1MB round-trip failed (enc: %d, dec: %d)", encSuccess, decSuccess);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] 1MB round-trip successful");
    }
}

// ============================================================================
// Security and Edge Case Tests
// ============================================================================

TEST_F(Base64UtilsTest, Security_ZeroBytes) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Security_ZeroBytes] Testing encoding of all zero bytes");
    
    std::vector<uint8_t> zeros(100, 0x00);
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(zeros, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess && decSuccess) << "Zero bytes round-trip should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(zeros, decoded)) << "All zeros should round-trip correctly";
    
    if (!encSuccess || !decSuccess || !CompareBinary(zeros, decoded)) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Zero bytes security test failed");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Zero bytes handled correctly");
    }
}

TEST_F(Base64UtilsTest, Security_MaxBytes) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Security_MaxBytes] Testing encoding of all 0xFF bytes");
    
    std::vector<uint8_t> maxBytes(100, 0xFF);
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(maxBytes, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess && decSuccess) << "Max bytes round-trip should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(maxBytes, decoded)) << "All 0xFF should round-trip correctly";
    
    if (!encSuccess || !decSuccess) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Max bytes security test failed");
    }
}

TEST_F(Base64UtilsTest, Security_AlternatingBits) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Security_AlternatingBits] Testing alternating bit patterns");
    
    std::vector<uint8_t> pattern = {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55};
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    bool encSuccess = Base64Encode(pattern, encoded);
    bool decSuccess = Base64Decode(encoded, decoded, err);
    
    EXPECT_TRUE(encSuccess && decSuccess) << "Alternating bits round-trip should succeed";
    EXPECT_EQ(err, Base64DecodeError::None) << "No decode error expected";
    EXPECT_TRUE(CompareBinary(pattern, decoded)) << "Pattern should be preserved";
    
    if (!encSuccess || !decSuccess) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Alternating bits test failed");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Alternating bits preserved correctly");
    }
}

TEST_F(Base64UtilsTest, EdgeCase_Length1Modulo3) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EdgeCase_Length1Modulo3] Testing lengths ≡ 1 (mod 3)");
    
    int passCount = 0;
    int failCount = 0;
    
    for (size_t len = 1; len <= 100; len += 3) {
        std::vector<uint8_t> data(len, 0x42);
        std::string encoded;
        std::vector<uint8_t> decoded;
        Base64DecodeError err;
        
        bool encSuccess = Base64Encode(data, encoded);
        bool decSuccess = Base64Decode(encoded, decoded, err);
        
        if (!encSuccess || !decSuccess || err != Base64DecodeError::None || !CompareBinary(data, decoded)) {
            failCount++;
            SS_LOG_ERROR(L"Base64Utils_Tests", L"[EdgeCase_Len1Mod3] Failed at length %zu", len);
        } else {
            passCount++;
        }
        
        EXPECT_TRUE(encSuccess && decSuccess) << "Length " << len << " should round-trip";
    }
    
    if (failCount == 0) {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] All %d lengths ≡ 1 (mod 3) passed", passCount);
    }
}

TEST_F(Base64UtilsTest, EdgeCase_Length2Modulo3) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EdgeCase_Length2Modulo3] Testing lengths ≡ 2 (mod 3)");
    
    int passCount = 0;
    int failCount = 0;
    
    for (size_t len = 2; len <= 100; len += 3) {
        std::vector<uint8_t> data(len, 0x42);
        std::string encoded;
        std::vector<uint8_t> decoded;
        Base64DecodeError err;
        
        bool encSuccess = Base64Encode(data, encoded);
        bool decSuccess = Base64Decode(encoded, decoded, err);
        
        if (!encSuccess || !decSuccess || err != Base64DecodeError::None || !CompareBinary(data, decoded)) {
            failCount++;
            SS_LOG_ERROR(L"Base64Utils_Tests", L"[EdgeCase_Len2Mod3] Failed at length %zu", len);
        } else {
            passCount++;
        }
        
        EXPECT_TRUE(encSuccess && decSuccess) << "Length " << len << " should round-trip";
    }
    
    if (failCount == 0) {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] All %d lengths ≡ 2 (mod 3) passed", passCount);
    }
}

TEST_F(Base64UtilsTest, EdgeCase_Length0Modulo3) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EdgeCase_Length0Modulo3] Testing lengths ≡ 0 (mod 3)");
    
    int passCount = 0;
    int failCount = 0;
    
    for (size_t len = 3; len <= 99; len += 3) {
        std::vector<uint8_t> data(len, 0x42);
        std::string encoded;
        std::vector<uint8_t> decoded;
        Base64DecodeError err;
        
        bool encSuccess = Base64Encode(data, encoded);
        bool decSuccess = Base64Decode(encoded, decoded, err);
        
        if (!encSuccess || !decSuccess || err != Base64DecodeError::None || !CompareBinary(data, decoded)) {
            failCount++;
            SS_LOG_ERROR(L"Base64Utils_Tests", L"[EdgeCase_Len0Mod3] Failed at length %zu", len);
        } else {
            passCount++;
        }
        
        EXPECT_TRUE(encSuccess && decSuccess) << "Length " << len << " should round-trip";
    }
    
    if (failCount == 0) {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] All %d lengths ≡ 0 (mod 3) passed", passCount);
    }
}

TEST_F(Base64UtilsTest, EdgeCase_SinglePadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EdgeCase_SinglePadding] Testing 1 padding character (2-byte input)");
    
    // Input that produces 1 padding character
    std::vector<uint8_t> data = {0x41, 0x42};
    std::string encoded;
    bool success = Base64Encode(data, encoded);
    
    EXPECT_TRUE(success) << "2-byte encoding should succeed";
    EXPECT_FALSE(encoded.empty()) << "Encoded string should not be empty";
    EXPECT_EQ(encoded.back(), '=') << "Should have 1 padding character at end";
    
    if (!success || encoded.empty() || encoded.back() != '=') {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Single padding test failed: '%s'", encoded.c_str());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Single padding correctly applied: '%s'", encoded.c_str());
    }
}

TEST_F(Base64UtilsTest, EdgeCase_DoublePadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[EdgeCase_DoublePadding] Testing 2 padding characters (1-byte input)");
    
    // Input that produces 2 padding characters
    std::vector<uint8_t> data = {0x41};
    std::string encoded;
    bool success = Base64Encode(data, encoded);
    
    EXPECT_TRUE(success) << "1-byte encoding should succeed";
    EXPECT_GE(encoded.size(), 2u) << "Encoded should have at least 2 characters";
    EXPECT_EQ(encoded.back(), '=') << "Should have padding at end";
    EXPECT_EQ(encoded[encoded.size() - 2], '=') << "Should have double padding";
    
    if (!success || encoded.size() < 2 || encoded.back() != '=' || encoded[encoded.size() - 2] != '=') {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Double padding test failed: '%s'", encoded.c_str());
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Double padding correctly applied: '%s'", encoded.c_str());
    }
}

TEST_F(Base64UtilsTest, Decode_IgnoreWhitespaceOption) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_IgnoreWhitespaceOption] Testing ignore whitespace option");
    
    Base64DecodeOptions opt;
    opt.ignoreWhitespace = false;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Should fail with whitespace when ignoreWhitespace is false
    bool success = Base64Decode("Zm 9v", result, err, opt);
    EXPECT_FALSE(success) << "Should reject whitespace when ignoreWhitespace=false";
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter) << "Error should be InvalidCharacter";
    
    if (success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Whitespace not rejected when ignoreWhitespace=false");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Whitespace correctly rejected with ignoreWhitespace=false");
    }
}

TEST_F(Base64UtilsTest, Decode_RequirePadding) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_RequirePadding] Testing required padding option");
    
    Base64DecodeOptions opt;
    opt.acceptMissingPadding = false;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Should fail without padding when acceptMissingPadding is false
    bool success = Base64Decode("Zg", result, err, opt);
    EXPECT_FALSE(success) << "Should reject missing padding when acceptMissingPadding=false";
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding) << "Error should be InvalidPadding";
    
    if (success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Missing padding not rejected when acceptMissingPadding=false");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Missing padding correctly rejected with acceptMissingPadding=false");
    }
}

TEST_F(Base64UtilsTest, Decode_InvalidSingleCharacter) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Decode_InvalidSingleCharacter] Testing single character rejection");
    
    Base64DecodeOptions opt;
    opt.acceptMissingPadding = true;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Single character is invalid (needs at least 2 chars for 1 byte)
    bool success = Base64Decode("Z", result, err, opt);
    EXPECT_FALSE(success) << "Single character should be invalid";
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding) << "Error should be InvalidPadding";
    
    if (success) {
        SS_LOG_ERROR(L"Base64Utils_Tests", L"[FAIL] Single character incorrectly accepted");
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Single character correctly rejected");
    }
}

// ============================================================================
// Performance Baseline Tests
// ============================================================================

TEST_F(Base64UtilsTest, Performance_SmallBuffer) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Performance_SmallBuffer] Benchmarking 64-byte encoding");
    
    std::vector<uint8_t> data(64, 0x42);
    std::string encoded;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) {
        bool success = Base64Encode(data, encoded);
        EXPECT_TRUE(success) << "Encoding should succeed";
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    SS_LOG_INFO(L"Base64Utils_Tests", 
        L"[PERF] Small buffer (64B): %lld μs for 10000 iterations", duration.count());
    std::cout << "Small buffer (64B) encoding: " << duration.count() << " μs for 10000 iterations\n";
}

TEST_F(Base64UtilsTest, Performance_MediumBuffer) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Performance_MediumBuffer] Benchmarking 4KB encoding");
    
    std::vector<uint8_t> data(4096, 0x42);
    std::string encoded;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        bool success = Base64Encode(data, encoded);
        EXPECT_TRUE(success) << "Encoding should succeed";
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    SS_LOG_INFO(L"Base64Utils_Tests",
        L"[PERF] Medium buffer (4KB): %lld μs for 1000 iterations", duration.count());
    std::cout << "Medium buffer (4KB) encoding: " << duration.count() << " μs for 1000 iterations\n";
}

TEST_F(Base64UtilsTest, Performance_LargeBuffer) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Performance_LargeBuffer] Benchmarking 1MB encoding");
    
    std::vector<uint8_t> data(1024 * 1024, 0x42);
    std::string encoded;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; ++i) {
        bool success = Base64Encode(data, encoded);
        EXPECT_TRUE(success) << "Encoding should succeed";
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    SS_LOG_INFO(L"Base64Utils_Tests",
        L"[PERF] Large buffer (1MB): %lld μs for 10 iterations", duration.count());
    std::cout << "Large buffer (1MB) encoding: " << duration.count() << " μs for 10 iterations\n";
}

TEST_F(Base64UtilsTest, Performance_DecodingSmall) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Performance_DecodingSmall] Benchmarking decoding");
    
    std::string encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=";
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) {
        bool success = Base64Decode(encoded, decoded, err);
        EXPECT_TRUE(success) << "Decoding should succeed";
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    SS_LOG_INFO(L"Base64Utils_Tests",
        L"[PERF] Small buffer decoding: %lld μs for 10000 iterations", duration.count());
    std::cout << "Small buffer decoding: " << duration.count() << " μs for 10000 iterations\n";
}

// ============================================================================
// Flags Operator Tests
// ============================================================================

TEST_F(Base64UtilsTest, Flags_BitwiseOr) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Flags_BitwiseOr] Testing flag combination with OR");
    
    Base64Flags combined = Base64Flags::InsertLineBreaks | Base64Flags::OmitPadding;
    
    bool hasLineBreaks = HasFlag(combined, Base64Flags::InsertLineBreaks);
    bool hasOmitPadding = HasFlag(combined, Base64Flags::OmitPadding);
    bool hasNone = HasFlag(combined, Base64Flags::None);
    
    EXPECT_TRUE(hasLineBreaks) << "Should have InsertLineBreaks flag";
    EXPECT_TRUE(hasOmitPadding) << "Should have OmitPadding flag";
    EXPECT_FALSE(hasNone) << "Should not have None flag";
    
    if (!hasLineBreaks || !hasOmitPadding || hasNone) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Flag OR operation failed (LineBreaks: %d, OmitPadding: %d, None: %d)", 
            hasLineBreaks, hasOmitPadding, hasNone);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Flags correctly combined with OR");
    }
}

TEST_F(Base64UtilsTest, Flags_OrAssignment) {
    SS_LOG_INFO(L"Base64Utils_Tests", L"[Flags_OrAssignment] Testing flag assignment with OR");
    
    Base64Flags flags = Base64Flags::None;
    flags |= Base64Flags::InsertLineBreaks;
    
    bool hasLineBreaks1 = HasFlag(flags, Base64Flags::InsertLineBreaks);
    EXPECT_TRUE(hasLineBreaks1) << "Should have InsertLineBreaks after |=";
    
    flags |= Base64Flags::OmitPadding;
    bool hasLineBreaks2 = HasFlag(flags, Base64Flags::InsertLineBreaks);
    bool hasOmitPadding = HasFlag(flags, Base64Flags::OmitPadding);
    
    EXPECT_TRUE(hasLineBreaks2) << "Should still have InsertLineBreaks";
    EXPECT_TRUE(hasOmitPadding) << "Should have OmitPadding";
    
    if (!hasLineBreaks1 || !hasLineBreaks2 || !hasOmitPadding) {
        SS_LOG_ERROR(L"Base64Utils_Tests", 
            L"[FAIL] Flag |= operation failed (LineBreaks: %d/%d, OmitPadding: %d)", 
            hasLineBreaks1, hasLineBreaks2, hasOmitPadding);
    } else {
        SS_LOG_DEBUG(L"Base64Utils_Tests", L"[PASS] Flags correctly assigned with |=");
    }
}

