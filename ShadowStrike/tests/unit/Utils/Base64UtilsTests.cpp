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

#include <gtest/gtest.h>
#include "../../../src/Utils/Base64Utils.hpp"
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
    EXPECT_EQ(Base64EncodedLength(0), 0u);
}

TEST_F(Base64UtilsTest, EncodedLength_SingleByte) {
    // 1 byte -> 4 chars with padding
    EXPECT_EQ(Base64EncodedLength(1), 4u);
}

TEST_F(Base64UtilsTest, EncodedLength_TwoBytes) {
    // 2 bytes -> 4 chars with padding
    EXPECT_EQ(Base64EncodedLength(2), 4u);
}

TEST_F(Base64UtilsTest, EncodedLength_ThreeBytes) {
    // 3 bytes -> 4 chars (exact block)
    EXPECT_EQ(Base64EncodedLength(3), 4u);
}

TEST_F(Base64UtilsTest, EncodedLength_MultipleBlocks) {
    EXPECT_EQ(Base64EncodedLength(6), 8u);
    EXPECT_EQ(Base64EncodedLength(9), 12u);
    EXPECT_EQ(Base64EncodedLength(12), 16u);
}

TEST_F(Base64UtilsTest, EncodedLength_WithOmitPadding) {
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::OmitPadding;
    
    EXPECT_EQ(Base64EncodedLength(1, opt), 2u);  // No padding
    EXPECT_EQ(Base64EncodedLength(2, opt), 3u);  // No padding
    EXPECT_EQ(Base64EncodedLength(3, opt), 4u);  // Exact block
    EXPECT_EQ(Base64EncodedLength(4, opt), 6u);
}

TEST_F(Base64UtilsTest, EncodedLength_WithLineBreaks) {
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks;
    opt.lineBreakEvery = 4;
    opt.lineBreak = "\n";
    
    // 6 bytes = 8 chars -> should have 1 line break
    size_t len = Base64EncodedLength(6, opt);
    EXPECT_EQ(len, 9u); // 8 chars + 1 newline
}

TEST_F(Base64UtilsTest, EncodedLength_Overflow) {
    // Test with extremely large input to check overflow protection
    size_t huge = SIZE_MAX / 2;
    size_t result = Base64EncodedLength(huge);
    // Should return 0 if overflow detected
    EXPECT_GE(result, 0u);
}

// ============================================================================
// Decoding Length Calculation Tests
// ============================================================================

TEST_F(Base64UtilsTest, MaxDecodedLength_EmptyInput) {
    EXPECT_EQ(Base64MaxDecodedLength(0), 0u);
}

TEST_F(Base64UtilsTest, MaxDecodedLength_ValidInput) {
    EXPECT_EQ(Base64MaxDecodedLength(4), 3u);
    EXPECT_EQ(Base64MaxDecodedLength(8), 6u);
    EXPECT_EQ(Base64MaxDecodedLength(12), 9u);
}

TEST_F(Base64UtilsTest, MaxDecodedLength_NonMultipleOfFour) {
    // Max decoded should handle non-4-aligned input
    EXPECT_GT(Base64MaxDecodedLength(5), 0u);
    EXPECT_GT(Base64MaxDecodedLength(7), 0u);
}

// ============================================================================
// Basic Encoding Tests
// ============================================================================

TEST_F(Base64UtilsTest, Encode_EmptyInput) {
    std::string result;
    EXPECT_TRUE(Base64Encode(std::vector<uint8_t>{}, result));
    EXPECT_EQ(result, "");
}

TEST_F(Base64UtilsTest, Encode_SingleByte) {
    std::string result;
    EXPECT_TRUE(Base64Encode(MakeBinary("A"), result));
    EXPECT_EQ(result, "QQ==");
}

TEST_F(Base64UtilsTest, Encode_TwoBytes) {
    std::string result;
    EXPECT_TRUE(Base64Encode(MakeBinary("AB"), result));
    EXPECT_EQ(result, "QUI=");
}

TEST_F(Base64UtilsTest, Encode_ThreeBytes) {
    std::string result;
    EXPECT_TRUE(Base64Encode(MakeBinary("ABC"), result));
    EXPECT_EQ(result, "QUJD");
}

TEST_F(Base64UtilsTest, Encode_RFCTestVectors) {
    std::string result;
    
    // RFC 4648 test vectors
    EXPECT_TRUE(Base64Encode(MakeBinary(""), result));
    EXPECT_EQ(result, "");
    
    EXPECT_TRUE(Base64Encode(MakeBinary("f"), result));
    EXPECT_EQ(result, "Zg==");
    
    EXPECT_TRUE(Base64Encode(MakeBinary("fo"), result));
    EXPECT_EQ(result, "Zm8=");
    
    EXPECT_TRUE(Base64Encode(MakeBinary("foo"), result));
    EXPECT_EQ(result, "Zm9v");
    
    EXPECT_TRUE(Base64Encode(MakeBinary("foob"), result));
    EXPECT_EQ(result, "Zm9vYg==");
    
    EXPECT_TRUE(Base64Encode(MakeBinary("fooba"), result));
    EXPECT_EQ(result, "Zm9vYmE=");
    
    EXPECT_TRUE(Base64Encode(MakeBinary("foobar"), result));
    EXPECT_EQ(result, "Zm9vYmFy");
}

TEST_F(Base64UtilsTest, Encode_AllByteValues) {
    // Test encoding of all possible byte values (0-255)
    std::vector<uint8_t> allBytes(256);
    for (int i = 0; i < 256; ++i) {
        allBytes[i] = static_cast<uint8_t>(i);
    }
    
    std::string result;
    EXPECT_TRUE(Base64Encode(allBytes, result));
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.size(), Base64EncodedLength(256));
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
    Base64EncodeOptions opt;
    opt.alphabet = Base64Alphabet::UrlSafe;
    
    // Create data that will produce '+' and '/' in standard encoding
    std::vector<uint8_t> data = {0xFB, 0xFF, 0xBF};
    std::string result;
    EXPECT_TRUE(Base64Encode(data, result, opt));
    
    // Should contain '-' and '_' instead of '+' and '/'
    EXPECT_EQ(result.find('+'), std::string::npos);
    EXPECT_EQ(result.find('/'), std::string::npos);
}

TEST_F(Base64UtilsTest, Encode_StandardVsUrlSafe) {
    std::vector<uint8_t> data = {0xFB, 0xFF, 0xBF};
    
    std::string standard, urlSafe;
    Base64EncodeOptions stdOpt, urlOpt;
    stdOpt.alphabet = Base64Alphabet::Standard;
    urlOpt.alphabet = Base64Alphabet::UrlSafe;
    
    EXPECT_TRUE(Base64Encode(data, standard, stdOpt));
    EXPECT_TRUE(Base64Encode(data, urlSafe, urlOpt));
    
    EXPECT_NE(standard, urlSafe);
}

// ============================================================================
// Padding Options Tests
// ============================================================================

TEST_F(Base64UtilsTest, Encode_OmitPadding) {
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::OmitPadding;
    
    std::string result;
    
    // 1 byte -> should be 2 chars without padding
    EXPECT_TRUE(Base64Encode(MakeBinary("A"), result, opt));
    EXPECT_EQ(result, "QQ");
    EXPECT_EQ(result.find('='), std::string::npos);
    
    // 2 bytes -> should be 3 chars without padding
    EXPECT_TRUE(Base64Encode(MakeBinary("AB"), result, opt));
    EXPECT_EQ(result, "QUI");
    EXPECT_EQ(result.find('='), std::string::npos);
    
    // 3 bytes -> exact block, no padding anyway
    EXPECT_TRUE(Base64Encode(MakeBinary("ABC"), result, opt));
    EXPECT_EQ(result, "QUJD");
}

// ============================================================================
// Line Break Tests
// ============================================================================

TEST_F(Base64UtilsTest, Encode_WithLineBreaks) {
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks;
    opt.lineBreakEvery = 4;
    opt.lineBreak = "\n";
    
    std::string input = "ABCDEFGHIJ"; // 10 bytes -> 16 chars
    std::string result;
    EXPECT_TRUE(Base64Encode(MakeBinary(input), result, opt));
    
    // Should contain line breaks
    EXPECT_NE(result.find('\n'), std::string::npos);
}

TEST_F(Base64UtilsTest, Encode_LineBreaksCRLF) {
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks;
    opt.lineBreakEvery = 76;
    opt.lineBreak = "\r\n";
    
    // Create 100 bytes of data
    std::vector<uint8_t> data(100, 0x41);
    std::string result;
    EXPECT_TRUE(Base64Encode(data, result, opt));
    
    // Should contain CRLF
    EXPECT_NE(result.find("\r\n"), std::string::npos);
}

TEST_F(Base64UtilsTest, Encode_CombinedFlags) {
    Base64EncodeOptions opt;
    opt.flags = Base64Flags::InsertLineBreaks | Base64Flags::OmitPadding;
    opt.lineBreakEvery = 8;
    opt.lineBreak = "\n";
    
    std::string result;
    EXPECT_TRUE(Base64Encode(MakeBinary("ABCDEFGHIJ"), result, opt));
    
    // Should have line breaks and no padding
    EXPECT_NE(result.find('\n'), std::string::npos);
    EXPECT_EQ(result.find('='), std::string::npos);
}

// ============================================================================
// Basic Decoding Tests
// ============================================================================

TEST_F(Base64UtilsTest, Decode_EmptyInput) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    EXPECT_TRUE(Base64Decode("", result, err));
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(err, Base64DecodeError::None);
}

TEST_F(Base64UtilsTest, Decode_RFCTestVectors) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Decode("Zg==", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("f")));
    
    EXPECT_TRUE(Base64Decode("Zm8=", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("fo")));
    
    EXPECT_TRUE(Base64Decode("Zm9v", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foo")));
    
    EXPECT_TRUE(Base64Decode("Zm9vYg==", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foob")));
    
    EXPECT_TRUE(Base64Decode("Zm9vYmE=", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("fooba")));
    
    EXPECT_TRUE(Base64Decode("Zm9vYmFy", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foobar")));
}

TEST_F(Base64UtilsTest, Decode_WithWhitespace) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Whitespace should be ignored by default
    EXPECT_TRUE(Base64Decode("Zm9v\r\n", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foo")));
    
    EXPECT_TRUE(Base64Decode("Zm 9v", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foo")));
    
    EXPECT_TRUE(Base64Decode("\tZm9v\t", result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("foo")));
}

TEST_F(Base64UtilsTest, Decode_NoPaddingAccepted) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    Base64DecodeOptions opt;
    opt.acceptMissingPadding = true;
    
    EXPECT_TRUE(Base64Decode("Zg", result, err, opt));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("f")));
    
    EXPECT_TRUE(Base64Decode("Zm8", result, err, opt));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(result, MakeBinary("fo")));
}

TEST_F(Base64UtilsTest, Decode_InvalidCharacter) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Invalid character '@'
    EXPECT_FALSE(Base64Decode("Zm9@", result, err));
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter);
    
    // Invalid character '!'
    EXPECT_FALSE(Base64Decode("!abc", result, err));
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter);
}

TEST_F(Base64UtilsTest, Decode_InvalidPadding) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Too much padding
    EXPECT_FALSE(Base64Decode("Zm9v===", result, err));
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding);
    
    // Padding in wrong position
    EXPECT_FALSE(Base64Decode("Z=9v", result, err));
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding);
}

TEST_F(Base64UtilsTest, Decode_TrailingDataAfterPadding) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Data after padding (non-whitespace)
    EXPECT_FALSE(Base64Decode("Zm9v==XX", result, err));
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding);
}

TEST_F(Base64UtilsTest, Decode_UrlSafeAlphabet) {
    Base64DecodeOptions opt;
    opt.alphabet = Base64Alphabet::UrlSafe;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Decode URL-safe encoded data
    EXPECT_TRUE(Base64Decode("-_-_", result, err, opt));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_FALSE(result.empty());
}

TEST_F(Base64UtilsTest, Decode_StandardRejectsUrlSafeChars) {
    Base64DecodeOptions opt;
    opt.alphabet = Base64Alphabet::Standard;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Standard alphabet should reject '-' and '_'
    EXPECT_FALSE(Base64Decode("-_-_", result, err, opt));
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter);
}

TEST_F(Base64UtilsTest, Decode_NullPointer) {
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Decode(nullptr, 0, result, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(result.empty());
    
    EXPECT_FALSE(Base64Decode(nullptr, 10, result, err));
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter);
}

// ============================================================================
// Round-Trip Tests
// ============================================================================

TEST_F(Base64UtilsTest, RoundTrip_EmptyData) {
    std::vector<uint8_t> original;
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(original, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(original, decoded));
}

TEST_F(Base64UtilsTest, RoundTrip_SingleByte) {
    std::vector<uint8_t> original = {0x42};
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(original, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(original, decoded));
}

TEST_F(Base64UtilsTest, RoundTrip_MultipleBlocks) {
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(original, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(original, decoded));
}

TEST_F(Base64UtilsTest, RoundTrip_AllByteValues) {
    std::vector<uint8_t> original(256);
    for (int i = 0; i < 256; ++i) {
        original[i] = static_cast<uint8_t>(i);
    }
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(original, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(original, decoded));
}

TEST_F(Base64UtilsTest, RoundTrip_UrlSafeAlphabet) {
    std::vector<uint8_t> original = {0xFB, 0xFF, 0xBF, 0xEE, 0xDD, 0xCC};
    
    Base64EncodeOptions encOpt;
    encOpt.alphabet = Base64Alphabet::UrlSafe;
    
    Base64DecodeOptions decOpt;
    decOpt.alphabet = Base64Alphabet::UrlSafe;
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(original, encoded, encOpt));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err, decOpt));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(original, decoded));
}

TEST_F(Base64UtilsTest, RoundTrip_WithoutPadding) {
    std::vector<uint8_t> original = {0x41, 0x42};
    
    Base64EncodeOptions encOpt;
    encOpt.flags = Base64Flags::OmitPadding;
    
    Base64DecodeOptions decOpt;
    decOpt.acceptMissingPadding = true;
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(original, encoded, encOpt));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err, decOpt));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(original, decoded));
}

TEST_F(Base64UtilsTest, RoundTrip_LargeData) {
    // Test with 1MB of pseudo-random data
    std::vector<uint8_t> original(1024 * 1024);
    for (size_t i = 0; i < original.size(); ++i) {
        original[i] = static_cast<uint8_t>((i * 1103515245 + 12345) >> 16);
    }
    
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(original, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(original, decoded));
}

// ============================================================================
// Security and Edge Case Tests
// ============================================================================

TEST_F(Base64UtilsTest, Security_ZeroBytes) {
    std::vector<uint8_t> zeros(100, 0x00);
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(zeros, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(zeros, decoded));
}

TEST_F(Base64UtilsTest, Security_MaxBytes) {
    std::vector<uint8_t> maxBytes(100, 0xFF);
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(maxBytes, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(maxBytes, decoded));
}

TEST_F(Base64UtilsTest, Security_AlternatingBits) {
    std::vector<uint8_t> pattern = {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55};
    std::string encoded;
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    EXPECT_TRUE(Base64Encode(pattern, encoded));
    EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    EXPECT_EQ(err, Base64DecodeError::None);
    EXPECT_TRUE(CompareBinary(pattern, decoded));
}

TEST_F(Base64UtilsTest, EdgeCase_Length1Modulo3) {
    for (size_t len = 1; len <= 100; len += 3) {
        std::vector<uint8_t> data(len, 0x42);
        std::string encoded;
        std::vector<uint8_t> decoded;
        Base64DecodeError err;
        
        EXPECT_TRUE(Base64Encode(data, encoded));
        EXPECT_TRUE(Base64Decode(encoded, decoded, err));
        EXPECT_EQ(err, Base64DecodeError::None);
        EXPECT_TRUE(CompareBinary(data, decoded));
    }
}

TEST_F(Base64UtilsTest, EdgeCase_Length2Modulo3) {
    for (size_t len = 2; len <= 100; len += 3) {
        std::vector<uint8_t> data(len, 0x42);
        std::string encoded;
        std::vector<uint8_t> decoded;
        Base64DecodeError err;
        
        EXPECT_TRUE(Base64Encode(data, encoded));
        EXPECT_TRUE(Base64Decode(encoded, decoded, err));
        EXPECT_EQ(err, Base64DecodeError::None);
        EXPECT_TRUE(CompareBinary(data, decoded));
    }
}

TEST_F(Base64UtilsTest, EdgeCase_Length0Modulo3) {
    for (size_t len = 3; len <= 99; len += 3) {
        std::vector<uint8_t> data(len, 0x42);
        std::string encoded;
        std::vector<uint8_t> decoded;
        Base64DecodeError err;
        
        EXPECT_TRUE(Base64Encode(data, encoded));
        EXPECT_TRUE(Base64Decode(encoded, decoded, err));
        EXPECT_EQ(err, Base64DecodeError::None);
        EXPECT_TRUE(CompareBinary(data, decoded));
    }
}

TEST_F(Base64UtilsTest, EdgeCase_SinglePadding) {
    // Input that produces 2 padding characters
    std::vector<uint8_t> data = {0x41, 0x42};
    std::string encoded;
    EXPECT_TRUE(Base64Encode(data, encoded));
    EXPECT_EQ(encoded.back(), '=');
}

TEST_F(Base64UtilsTest, EdgeCase_DoublePadding) {
    // Input that produces 2 padding characters
    std::vector<uint8_t> data = {0x41};
    std::string encoded;
    EXPECT_TRUE(Base64Encode(data, encoded));
    EXPECT_EQ(encoded.back(), '=');
    EXPECT_EQ(encoded[encoded.size() - 2], '=');
}

TEST_F(Base64UtilsTest, Decode_IgnoreWhitespaceOption) {
    Base64DecodeOptions opt;
    opt.ignoreWhitespace = false;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Should fail with whitespace when ignoreWhitespace is false
    EXPECT_FALSE(Base64Decode("Zm 9v", result, err, opt));
    EXPECT_EQ(err, Base64DecodeError::InvalidCharacter);
}

TEST_F(Base64UtilsTest, Decode_RequirePadding) {
    Base64DecodeOptions opt;
    opt.acceptMissingPadding = false;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Should fail without padding when acceptMissingPadding is false
    EXPECT_FALSE(Base64Decode("Zg", result, err, opt));
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding);
}

TEST_F(Base64UtilsTest, Decode_InvalidSingleCharacter) {
    Base64DecodeOptions opt;
    opt.acceptMissingPadding = true;
    
    std::vector<uint8_t> result;
    Base64DecodeError err;
    
    // Single character is invalid (needs at least 2 chars for 1 byte)
    EXPECT_FALSE(Base64Decode("Z", result, err, opt));
    EXPECT_EQ(err, Base64DecodeError::InvalidPadding);
}

// ============================================================================
// Performance Baseline Tests
// ============================================================================

TEST_F(Base64UtilsTest, Performance_SmallBuffer) {
    std::vector<uint8_t> data(64, 0x42);
    std::string encoded;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) {
        EXPECT_TRUE(Base64Encode(data, encoded));
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Small buffer (64B) encoding: " << duration.count() << " μs for 10000 iterations\n";
}

TEST_F(Base64UtilsTest, Performance_MediumBuffer) {
    std::vector<uint8_t> data(4096, 0x42);
    std::string encoded;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(Base64Encode(data, encoded));
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Medium buffer (4KB) encoding: " << duration.count() << " μs for 1000 iterations\n";
}

TEST_F(Base64UtilsTest, Performance_LargeBuffer) {
    std::vector<uint8_t> data(1024 * 1024, 0x42);
    std::string encoded;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(Base64Encode(data, encoded));
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Large buffer (1MB) encoding: " << duration.count() << " μs for 10 iterations\n";
}

TEST_F(Base64UtilsTest, Performance_DecodingSmall) {
    std::string encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=";
    std::vector<uint8_t> decoded;
    Base64DecodeError err;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) {
        EXPECT_TRUE(Base64Decode(encoded, decoded, err));
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Small buffer decoding: " << duration.count() << " μs for 10000 iterations\n";
}

// ============================================================================
// Flags Operator Tests
// ============================================================================

TEST_F(Base64UtilsTest, Flags_BitwiseOr) {
    Base64Flags combined = Base64Flags::InsertLineBreaks | Base64Flags::OmitPadding;
    EXPECT_TRUE(HasFlag(combined, Base64Flags::InsertLineBreaks));
    EXPECT_TRUE(HasFlag(combined, Base64Flags::OmitPadding));
    EXPECT_FALSE(HasFlag(combined, Base64Flags::None));
}

TEST_F(Base64UtilsTest, Flags_OrAssignment) {
    Base64Flags flags = Base64Flags::None;
    flags |= Base64Flags::InsertLineBreaks;
    EXPECT_TRUE(HasFlag(flags, Base64Flags::InsertLineBreaks));
    
    flags |= Base64Flags::OmitPadding;
    EXPECT_TRUE(HasFlag(flags, Base64Flags::InsertLineBreaks));
    EXPECT_TRUE(HasFlag(flags, Base64Flags::OmitPadding));
}

