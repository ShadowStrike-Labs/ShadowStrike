/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "CryptoDetector.hpp"
#include "../Common/Types.hpp"
#include "../Common/Errors.hpp"
#include "../Core/Memory/VirtualMemory.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Hard Caps — prevent resource exhaustion during analysis
// ============================================================================

static constexpr uint32_t kMaxFindings            = 10'000;
static constexpr uint32_t kMaxXorRecords          = 50'000;
static constexpr uint32_t kMaxApiCallRecords      = 10'000;
static constexpr uint32_t kMaxFlaggedAddresses    = 50'000;
static constexpr uint32_t kMaxKeyMaterialBytes    = 256;
static constexpr GuestSize kMaxScanRegionSize     = 64ULL * 1024 * 1024;
static constexpr uint32_t kPageScanBuffer         = 4096;
static constexpr uint32_t kMaxPagesPerScan        = 16384;
static constexpr uint32_t kXorLoopThreshold       = 16;
static constexpr double   kHighEntropyThreshold   = 7.0;
static constexpr uint32_t kMinCustomCryptoSize    = 1024;
static constexpr float    kConfidenceAESSbox       = 0.95f;
static constexpr float    kConfidenceAESInvSbox    = 0.95f;
static constexpr float    kConfidenceRC4KSA        = 0.80f;
static constexpr float    kConfidenceDES           = 0.85f;
static constexpr float    kConfidenceSHA256        = 0.90f;
static constexpr float    kConfidenceSHA1          = 0.90f;
static constexpr float    kConfidenceMD5           = 0.90f;
static constexpr float    kConfidenceChaCha20      = 0.90f;
static constexpr float    kConfidenceCRC32         = 0.85f;
static constexpr float    kConfidenceXorSingle     = 0.85f;
static constexpr float    kConfidenceXorMulti      = 0.75f;
static constexpr float    kConfidenceCryptoAPI     = 0.95f;
static constexpr float    kConfidenceBlowfish      = 0.80f;
static constexpr float    kConfidenceBlowfishFull  = 0.92f;
static constexpr float    kConfidenceRSA           = 0.85f;
static constexpr float    kConfidenceTwofish       = 0.90f;
static constexpr float    kConfidenceSerpent       = 0.85f;
static constexpr float    kConfidenceECC           = 0.92f;
static constexpr float    kConfidenceBase64        = 0.80f;
static constexpr float    kConfidenceBase32        = 0.80f;
static constexpr float    kConfidenceHexEncoding   = 0.75f;
static constexpr float    kConfidenceAPIHashing    = 0.90f;
static constexpr float    kConfidenceStackString   = 0.75f;
static constexpr float    kConfidenceJunkCode      = 0.70f;
static constexpr float    kConfidenceRansomware    = 0.95f;
static constexpr float    kConfidenceCustom        = 0.40f;

// ============================================================================
// AES Rijndael S-box (forward)
// ============================================================================

static constexpr std::array<uint8_t, 256> kAesSbox = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

// ============================================================================
// AES Rijndael Inverse S-box
// ============================================================================

static constexpr std::array<uint8_t, 256> kAesInvSbox = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

// ============================================================================
// DES Initial Permutation Table (64 entries)
// ============================================================================

static constexpr std::array<uint8_t, 64> kDesIP = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
};

// ============================================================================
// DES Final Permutation Table (64 entries)
// ============================================================================

static constexpr std::array<uint8_t, 64> kDesFP = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
};

// ============================================================================
// DES S-boxes (8 boxes × 64 entries each = 512 total)
// ============================================================================

static constexpr std::array<std::array<uint8_t, 64>, 8> kDesSboxes = {{
    // S1
    {{
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
    }},
    // S2
    {{
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
    }},
    // S3
    {{
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
    }},
    // S4
    {{
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
    }},
    // S5
    {{
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
    }},
    // S6
    {{
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
    }},
    // S7
    {{
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
    }},
    // S8
    {{
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6,  2,  0, 14,  9, 11,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
    }},
}};

// ============================================================================
// SHA-256 Initial Hash Values (H0..H7)
// ============================================================================

static constexpr std::array<uint32_t, 8> kSha256Init = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

// ============================================================================
// SHA-256 Round Constants K (64 × uint32_t)
// ============================================================================

static constexpr std::array<uint32_t, 64> kSha256K = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

// ============================================================================
// SHA-1 Initial Hash Values
// ============================================================================

static constexpr std::array<uint32_t, 5> kSha1Init = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
};

// ============================================================================
// MD5 Initial Hash Values
// ============================================================================

static constexpr std::array<uint32_t, 4> kMd5Init = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
};

// ============================================================================
// MD5 T Table (64 × uint32_t — derived from floor(2^32 * abs(sin(i+1))))
// ============================================================================

static constexpr std::array<uint32_t, 64> kMd5T = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
};

// ============================================================================
// Blowfish P-array initial values (first 4 for quick detection)
// ============================================================================

static constexpr std::array<uint32_t, 4> kBlowfishPInit = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
};

// Full Blowfish P-array (18 entries — digits of pi)
static constexpr std::array<uint32_t, 18> kBlowfishPFull = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B,
};

// Blowfish S-box 0 initial values (first 16 of 256 entries)
static constexpr std::array<uint32_t, 16> kBlowfishS0Head = {
    0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7,
    0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
    0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
    0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E,
};

// ============================================================================
// ChaCha20 / Salsa20 sigma constants
// ============================================================================

static constexpr std::array<uint8_t, 16> kChaCha20Sigma32 = {
    0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33,
    0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B,
};

static constexpr std::array<uint8_t, 16> kChaCha20Sigma16 = {
    0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x31,
    0x36, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B,
};

// ============================================================================
// RSA ASN.1 DER header patterns
// ============================================================================

// SEQUENCE + SEQUENCE + OID for rsaEncryption (1.2.840.113549.1.1.1)
static constexpr std::array<uint8_t, 11> kRsaOidHeader = {
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01,
};

// RSA PKCS#8 private key header: SEQUENCE + INTEGER version 0
static constexpr std::array<uint8_t, 3> kRsaPkcs8Prefix = {
    0x02, 0x01, 0x00,
};

// ============================================================================
// CRC32 Table (generated with polynomial 0xEDB88320)
// ============================================================================

namespace detail {

consteval std::array<uint32_t, 256> GenerateCrc32Table() noexcept {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    return table;
}

} // namespace detail

static constexpr std::array<uint32_t, 256> kCrc32Table = detail::GenerateCrc32Table();

// ============================================================================
// Twofish Q-permutation tables (first 16 entries for fast fingerprinting)
// ============================================================================

static constexpr std::array<uint8_t, 16> kTwofishQ0Head = {
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
};

static constexpr std::array<uint8_t, 16> kTwofishQ1Head = {
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
};

// Twofish MDS matrix (4×4 over GF(2^8), polynomial 0x169)
static constexpr std::array<uint8_t, 16> kTwofishMDS = {
    0x01, 0xEF, 0x5B, 0x5B,
    0x5B, 0xEF, 0xEF, 0x01,
    0xEF, 0x5B, 0x01, 0xEF,
    0xEF, 0x01, 0xEF, 0x5B,
};

// Twofish RS (Reed-Solomon) matrix (4×8, used for key-dependent S-boxes)
static constexpr std::array<uint8_t, 32> kTwofishRS = {
    0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E,
    0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5,
    0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19,
    0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03,
};

// ============================================================================
// Serpent S-boxes (8 unique 4-bit permutations, 16 entries each)
// ============================================================================

static constexpr std::array<std::array<uint8_t, 16>, 8> kSerpentSboxes = {{
    {{  3,  8, 15,  1, 10,  6,  5, 11, 14, 13,  4,  2,  7,  0,  9, 12 }},
    {{ 15, 12,  2,  7,  9,  0,  5, 10,  1, 11, 14,  8,  6, 13,  3,  4 }},
    {{  8,  6,  7,  9,  3, 12, 10, 15, 13,  1, 14,  4,  0, 11,  5,  2 }},
    {{  0, 15, 11,  8, 12,  9,  6,  3, 13,  1,  2,  4, 10,  7,  5, 14 }},
    {{  1, 15,  8,  3, 12,  0, 11,  6,  2,  5,  4, 10,  9, 14,  7, 13 }},
    {{ 15,  5,  2, 11,  4, 10,  9, 12,  0,  3, 14,  8, 13,  6,  7,  1 }},
    {{  7,  2, 12,  5,  8,  4,  6, 11, 14,  9,  1, 15, 13,  3, 10,  0 }},
    {{  1, 13, 15,  0, 14,  8,  2, 11,  7,  4, 12, 10,  9,  3,  5,  6 }},
}};

// Serpent round constant (phi = 0x9E3779B9, the golden ratio fractional part)
static constexpr uint32_t kSerpentPhi = 0x9E3779B9;

// ============================================================================
// Elliptic Curve Constants (ECDSA/ECDH — big-endian coordinates)
// ============================================================================

// secp256k1 generator point Gx (Bitcoin curve, used by some ransomware)
static constexpr std::array<uint8_t, 32> kSecp256k1Gx = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
};

// secp256k1 generator point Gy
static constexpr std::array<uint8_t, 32> kSecp256k1Gy = {
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
};

// NIST P-256 (secp256r1) generator point Gx
static constexpr std::array<uint8_t, 32> kP256Gx = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
};

// NIST P-256 (secp256r1) generator point Gy
static constexpr std::array<uint8_t, 32> kP256Gy = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
};

// NIST P-256 order n (big-endian)
static constexpr std::array<uint8_t, 32> kP256Order = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

// Curve25519 prime p = 2^255 − 19 (little-endian, as used in NaCl/libsodium)
static constexpr std::array<uint8_t, 32> kCurve25519Prime = {
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
};

// ============================================================================
// Base64 / Base32 / Hex Encoding Alphabets
// ============================================================================

static constexpr std::array<uint8_t, 64> kBase64Alphabet = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/',
};

static constexpr std::array<uint8_t, 32> kBase32Alphabet = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '2','3','4','5','6','7',
};

static constexpr std::array<uint8_t, 16> kHexAlphabetLower = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
};

static constexpr std::array<uint8_t, 16> kHexAlphabetUpper = {
    '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F',
};

// ============================================================================
// Well-known API hash constants (ROR13, CRC32, djb2, FNV-1a)
// Used by shellcode / packers to resolve imports without plaintext strings
// ============================================================================

struct APIHashEntry {
    uint32_t    hash;
    const char* apiName;
    const char* hashAlgorithm;
};

static constexpr APIHashEntry kKnownAPIHashes[] = {
    // ROR13 hashes (Metasploit block_api / shellcode convention)
    { 0x0726774C, "LoadLibraryA",            "ror13" },
    { 0x7C0DFCAA, "GetProcAddress",          "ror13" },
    { 0x0E8AFE98, "VirtualAlloc",            "ror13" },
    { 0x56A2B5F0, "kernel32.dll",            "ror13" },
    { 0x9DBD95A6, "GetSystemDirectoryA",     "ror13" },
    { 0x6F721347, "RtlExitUserThread",       "ror13" },
    { 0x160D6838, "CreateFileA",             "ror13" },
    { 0x4FDAF6DA, "CreateFileW",             "ror13" },
    { 0xE553A458, "VirtualFree",             "ror13" },
    { 0xE7BDD8C5, "VirtualProtect",          "ror13" },
    { 0x5BAE572D, "WriteFile",               "ror13" },
    { 0xBB5F9EAD, "ReadFile",               "ror13" },
    { 0xE035F044, "Sleep",                   "ror13" },
    { 0x006B8029, "WinExec",                "ror13" },
    { 0x876F8B31, "WSAStartup",             "ror13" },
    { 0x863FCC79, "CreateProcessA",          "ror13" },
    { 0xE13BEC74, "CreateRemoteThread",      "ror13" },
    { 0x528796C6, "CloseHandle",             "ror13" },
    { 0x300F2F0B, "NtAllocateVirtualMemory", "ror13" },
    { 0x0A2A1DE0, "ExitProcess",             "ror13" },
    { 0x4C0297FA, "InternetOpenA",           "ror13" },
    { 0x69B34E3B, "InternetOpenUrlA",        "ror13" },
    { 0xC69F8957, "InternetConnectA",        "ror13" },
    { 0x3B2E55EB, "HttpOpenRequestA",        "ror13" },
    { 0x7B18062D, "HttpSendRequestA",        "ror13" },
    // CRC32-based API hashes (APT32 / OceanLotus convention)
    { 0xC8AC8026, "LoadLibraryA",            "crc32" },
    { 0x1FC0EAEE, "GetProcAddress",          "crc32" },
    { 0x697A6AFE, "VirtualAlloc",            "crc32" },
    { 0x5B8ACA33, "VirtualProtect",          "crc32" },
    { 0x4FD18963, "CreateThread",            "crc32" },
    // djb2 API hashes
    { 0x0B8029BD, "LoadLibraryA",            "djb2"  },
    { 0x5FBFF0FB, "GetProcAddress",          "djb2"  },
    { 0xEE0944B3, "VirtualAlloc",            "djb2"  },
    // FNV-1a API hashes
    { 0xCF31BB1F, "LoadLibraryA",            "fnv1a" },
    { 0x735305AC, "GetProcAddress",          "fnv1a" },
    { 0x85092E2B, "VirtualAlloc",            "fnv1a" },
};

static constexpr size_t kKnownAPIHashCount =
    sizeof(kKnownAPIHashes) / sizeof(kKnownAPIHashes[0]);

// Minimum API hashes found in a 256-byte window to flag as API hash resolution
static constexpr uint32_t kMinAPIHashCluster = 2;

// ============================================================================
// Crypto API names to track
// ============================================================================

namespace {

struct CryptoApiEntry {
    std::string_view name;
    CryptoAlgorithm  mappedAlgo;
    bool             isEncryption;
};

static constexpr CryptoApiEntry kCryptoApis[] = {
    { "BCryptOpenAlgorithmProvider", CryptoAlgorithm::Unknown,         false },
    { "BCryptGenerateSymmetricKey",  CryptoAlgorithm::CustomSymmetric, false },
    { "BCryptEncrypt",               CryptoAlgorithm::CustomSymmetric, true  },
    { "BCryptDecrypt",               CryptoAlgorithm::CustomSymmetric, false },
    { "CryptAcquireContext",         CryptoAlgorithm::Unknown,         false },
    { "CryptCreateHash",            CryptoAlgorithm::CustomHash,      false },
    { "CryptEncrypt",               CryptoAlgorithm::CustomSymmetric, true  },
    { "CryptDecrypt",               CryptoAlgorithm::CustomSymmetric, false },
    { "CryptDeriveKey",             CryptoAlgorithm::CustomSymmetric, false },
    { "CryptImportKey",             CryptoAlgorithm::CustomSymmetric, false },
    { "CryptGenRandom",             CryptoAlgorithm::Unknown,         false },
    { "BCryptGenRandom",            CryptoAlgorithm::Unknown,         false },
};

static constexpr size_t kCryptoApiCount = sizeof(kCryptoApis) / sizeof(kCryptoApis[0]);

// ============================================================================
// Helpers
// ============================================================================

[[nodiscard]] double ComputeShannonEntropy(
    const uint8_t* data, size_t size) noexcept
{
    if (!data || size == 0) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (size_t i = 0; i < size; ++i) {
        ++freq[data[i]];
    }

    const double total = static_cast<double>(size);
    double entropy = 0.0;
    for (uint32_t count : freq) {
        if (count == 0) continue;
        const double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

[[nodiscard]] constexpr uint32_t ByteSwap32(uint32_t val) noexcept {
    return ((val & 0x000000FFu) << 24) |
           ((val & 0x0000FF00u) <<  8) |
           ((val & 0x00FF0000u) >>  8) |
           ((val & 0xFF000000u) >> 24);
}

[[nodiscard]] const char* AlgorithmName(CryptoAlgorithm algo) noexcept {
    switch (algo) {
        case CryptoAlgorithm::Unknown:           return "Unknown";
        case CryptoAlgorithm::AES:               return "AES";
        case CryptoAlgorithm::AES_Inv:           return "AES (Inverse/Decryption)";
        case CryptoAlgorithm::RC4:               return "RC4";
        case CryptoAlgorithm::XOR_Single:        return "XOR (Single-byte)";
        case CryptoAlgorithm::XOR_Multi:         return "XOR (Multi-byte)";
        case CryptoAlgorithm::RSA:               return "RSA";
        case CryptoAlgorithm::DES:               return "DES";
        case CryptoAlgorithm::TripleDES:         return "Triple DES";
        case CryptoAlgorithm::ChaCha20:          return "ChaCha20";
        case CryptoAlgorithm::Salsa20:           return "Salsa20";
        case CryptoAlgorithm::Blowfish:          return "Blowfish";
        case CryptoAlgorithm::Twofish:           return "Twofish";
        case CryptoAlgorithm::Serpent:           return "Serpent";
        case CryptoAlgorithm::CRC32:             return "CRC32";
        case CryptoAlgorithm::MD5:               return "MD5";
        case CryptoAlgorithm::SHA1:              return "SHA-1";
        case CryptoAlgorithm::SHA256:            return "SHA-256";
        case CryptoAlgorithm::SHA512:            return "SHA-512";
        case CryptoAlgorithm::ECC:               return "ECC (Elliptic Curve)";
        case CryptoAlgorithm::Base64:            return "Base64 Encoding";
        case CryptoAlgorithm::Base32:            return "Base32 Encoding";
        case CryptoAlgorithm::HexEncoding:       return "Hex Encoding";
        case CryptoAlgorithm::APIHashing:        return "API Hashing";
        case CryptoAlgorithm::StackString:       return "Stack String Construction";
        case CryptoAlgorithm::JunkCode:          return "Junk Code / NOP Sled";
        case CryptoAlgorithm::RansomwarePattern: return "Ransomware Crypto Pattern";
        case CryptoAlgorithm::CustomSymmetric:   return "Custom Symmetric";
        case CryptoAlgorithm::CustomHash:        return "Custom Hash";
        case CryptoAlgorithm::CustomStream:      return "Custom Stream";
    }
    return "Unknown";
}

// Read a uint32_t from a byte buffer in little-endian order
[[nodiscard]] uint32_t ReadU32LE(const uint8_t* p) noexcept {
    uint32_t val = 0;
    std::memcpy(&val, p, 4);
    return val;
}

// Read a uint32_t from a byte buffer in big-endian order
[[nodiscard]] uint32_t ReadU32BE(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
           (static_cast<uint32_t>(p[3]));
}

} // anonymous namespace

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct CryptoDetector::Impl {

    // -----------------------------------------------------------------------
    // XOR operation tracking
    // -----------------------------------------------------------------------

    struct XorOpRecord {
        uint8_t      key            = 0;
        uint32_t     hitCount       = 0;
        GuestAddress firstDataAddr  = 0;
        GuestAddress lastDataAddr   = 0;
        uint32_t     lastOpSize     = 0;
    };

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    const EmulationConfig& config;

    std::vector<CryptoFinding>                    findings;
    std::unordered_map<GuestAddress, XorOpRecord> xorRecords;
    std::vector<std::string>                      apiCallsSeen;
    std::unordered_set<GuestAddress>              flaggedAddresses;

    bool hasNetworkActivity = false;
    uint32_t cryptGenRandomCount = 0;  // Tracks CryptGenRandom/BCryptGenRandom calls

    mutable std::shared_mutex mutex;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    explicit Impl(const EmulationConfig& cfg) noexcept
        : config(cfg)
    {
        findings.reserve(256);
        apiCallsSeen.reserve(64);
    }

    // -----------------------------------------------------------------------
    // Capped insertion helpers
    // -----------------------------------------------------------------------

    bool AddFinding(CryptoFinding&& f) noexcept {
        if (findings.size() >= kMaxFindings) return false;
        findings.push_back(std::move(f));
        return true;
    }

    bool IsAlreadyFlagged(GuestAddress addr) const noexcept {
        return flaggedAddresses.count(addr) > 0;
    }

    void MarkFlagged(GuestAddress addr) noexcept {
        if (flaggedAddresses.size() < kMaxFlaggedAddresses) {
            flaggedAddresses.insert(addr);
        }
    }

    // -----------------------------------------------------------------------
    // Core scan — dispatches sub-scanners
    // -----------------------------------------------------------------------

    void ScanBuffer(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (!data || len == 0) return;
        if (len > kMaxScanRegionSize) len = static_cast<size_t>(kMaxScanRegionSize);

        ScanForAesSbox(data, len, base);
        ScanForAesInvSbox(data, len, base);
        ScanForRC4KSA(data, len, base);
        ScanForDESTables(data, len, base);
        ScanForSha256Constants(data, len, base);
        ScanForSha1Constants(data, len, base);
        ScanForMd5Constants(data, len, base);
        ScanForChaCha20Salsa20(data, len, base);
        ScanForCrc32Table(data, len, base);
        ScanForBlowfish(data, len, base);
        ScanForRSAHeaders(data, len, base);
        ScanForTwofish(data, len, base);
        ScanForSerpent(data, len, base);
        ScanForECCConstants(data, len, base);
        ScanForEncodingTables(data, len, base);
        ScanForAPIHashes(data, len, base);
        ScanForObfuscationPatterns(data, len, base);
        ScanForCustomCrypto(data, len, base);
    }

    // -----------------------------------------------------------------------
    // 1. AES S-box detection
    // -----------------------------------------------------------------------

    void ScanForAesSbox(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 256) return;

        const size_t searchEnd = len - 256;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            // Check for exact contiguous match
            if (std::memcmp(data + i, kAesSbox.data(), 256) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm   = CryptoAlgorithm::AES;
                f.address     = addr;
                f.size        = 256;
                f.confidence  = kConfidenceAESSbox;
                f.description = "AES forward S-box (Rijndael) detected — exact contiguous match";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += 255;
                continue;
            }

            // Check for row-transposed S-box (16×16 → column-major order)
            if (CheckRowTransposedSbox(data + i, kAesSbox)) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm   = CryptoAlgorithm::AES;
                f.address     = addr;
                f.size        = 256;
                f.confidence  = kConfidenceAESSbox;
                f.description = "AES forward S-box (Rijndael) detected — row-transposed layout";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += 255;
                continue;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 2. AES Inverse S-box detection
    // -----------------------------------------------------------------------

    void ScanForAesInvSbox(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 256) return;

        const size_t searchEnd = len - 256;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, kAesInvSbox.data(), 256) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::AES_Inv;
                f.address      = addr;
                f.size         = 256;
                f.confidence   = kConfidenceAESInvSbox;
                f.description  = "AES inverse S-box detected — indicates AES decryption capability";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i += 255;
                continue;
            }

            if (CheckRowTransposedSbox(data + i, kAesInvSbox)) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::AES_Inv;
                f.address      = addr;
                f.size         = 256;
                f.confidence   = kConfidenceAESInvSbox;
                f.description  = "AES inverse S-box detected — row-transposed layout";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i += 255;
                continue;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Row-transposed S-box check (16×16 matrix stored column-major)
    // -----------------------------------------------------------------------

    [[nodiscard]] static bool CheckRowTransposedSbox(
        const uint8_t* candidate,
        const std::array<uint8_t, 256>& reference) noexcept
    {
        // Reference is row-major: reference[row * 16 + col]
        // Candidate might be column-major: candidate[col * 16 + row]
        for (uint32_t row = 0; row < 16; ++row) {
            for (uint32_t col = 0; col < 16; ++col) {
                if (candidate[col * 16 + row] != reference[row * 16 + col]) {
                    return false;
                }
            }
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // 3. RC4 KSA detection — 256-byte permutation of 0..255
    // -----------------------------------------------------------------------

    void ScanForRC4KSA(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 256) return;

        // Skip if it's an exact AES S-box (already flagged)
        const size_t searchEnd = len - 256;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (IsPermutationOf0To255(data + i)) {
                // Exclude identity permutation (all zeros initially)
                if (IsIdentityPermutation(data + i)) continue;

                // Exclude known S-boxes
                if (std::memcmp(data + i, kAesSbox.data(), 256) == 0) continue;
                if (std::memcmp(data + i, kAesInvSbox.data(), 256) == 0) continue;

                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::RC4;
                f.address      = addr;
                f.size         = 256;
                f.confidence   = kConfidenceRC4KSA;
                f.description  = "RC4 state array detected — 256-byte permutation of 0..255 (post-KSA)";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += 255;
            }
        }
    }

    [[nodiscard]] static bool IsPermutationOf0To255(const uint8_t* block) noexcept {
        std::array<bool, 256> seen{};
        for (uint32_t j = 0; j < 256; ++j) {
            if (seen[block[j]]) return false;
            seen[block[j]] = true;
        }
        return true;
    }

    [[nodiscard]] static bool IsIdentityPermutation(const uint8_t* block) noexcept {
        for (uint32_t j = 0; j < 256; ++j) {
            if (block[j] != static_cast<uint8_t>(j)) return false;
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // 4. DES table detection
    // -----------------------------------------------------------------------

    void ScanForDESTables(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        ScanForDesIPTable(data, len, base);
        ScanForDesFPTable(data, len, base);
        ScanForDesSboxes(data, len, base);
    }

    void ScanForDesIPTable(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 64) return;
        const size_t searchEnd = len - 64;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, kDesIP.data(), 64) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm   = CryptoAlgorithm::DES;
                f.address     = addr;
                f.size        = 64;
                f.confidence  = kConfidenceDES;
                f.description = "DES Initial Permutation table detected";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += 63;
            }
        }
    }

    void ScanForDesFPTable(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 64) return;
        const size_t searchEnd = len - 64;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, kDesFP.data(), 64) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm   = CryptoAlgorithm::DES;
                f.address     = addr;
                f.size        = 64;
                f.confidence  = kConfidenceDES;
                f.description = "DES Final Permutation table detected";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += 63;
            }
        }
    }

    void ScanForDesSboxes(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Each DES S-box is 64 bytes. Scan for each independently.
        if (len < 64) return;
        const size_t searchEnd = len - 64;

        for (uint32_t sboxIdx = 0; sboxIdx < 8; ++sboxIdx) {
            for (size_t i = 0; i <= searchEnd; ++i) {
                const GuestAddress addr = base + static_cast<GuestAddress>(i);
                if (IsAlreadyFlagged(addr)) continue;

                if (std::memcmp(data + i, kDesSboxes[sboxIdx].data(), 64) == 0) {
                    MarkFlagged(addr);

                    std::string desc = "DES S-box S";
                    desc += std::to_string(sboxIdx + 1);
                    desc += " detected";

                    // If multiple consecutive S-boxes are present, flag as full DES
                    uint32_t consecutiveBoxes = 1;
                    size_t nextOffset = i + 64;
                    uint32_t nextBox = sboxIdx + 1;
                    while (nextBox < 8 && nextOffset + 64 <= len) {
                        if (std::memcmp(data + nextOffset,
                                        kDesSboxes[nextBox].data(), 64) == 0) {
                            ++consecutiveBoxes;
                            MarkFlagged(base + static_cast<GuestAddress>(nextOffset));
                            nextOffset += 64;
                            ++nextBox;
                        } else {
                            break;
                        }
                    }

                    CryptoFinding f;
                    f.algorithm   = CryptoAlgorithm::DES;
                    f.address     = addr;

                    if (consecutiveBoxes >= 4) {
                        f.size        = static_cast<GuestSize>(consecutiveBoxes) * 64;
                        f.confidence  = kConfidenceDES;
                        f.description = "DES S-box block detected (" +
                                        std::to_string(consecutiveBoxes) +
                                        " consecutive S-boxes)";
                        if (consecutiveBoxes == 8) {
                            f.description = "Complete DES S-box array detected (all 8 S-boxes)";
                        }
                    } else {
                        f.size        = 64;
                        f.confidence  = kConfidenceDES * 0.8f;
                        f.description = std::move(desc);
                    }

                    f.isEncryption = true;
                    AddFinding(std::move(f));
                    i = nextOffset - 1; // skip past matched region
                    break; // move to next S-box index
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 5. SHA-256 constant detection
    // -----------------------------------------------------------------------

    void ScanForSha256Constants(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Scan for H0..H7 init values (32 bytes as uint32_t)
        ScanForU32Array(data, len, base,
                        kSha256Init.data(), kSha256Init.size(),
                        CryptoAlgorithm::SHA256,
                        "SHA-256 initial hash values (H0..H7) detected",
                        false);

        // Scan for K round constants (256 bytes as uint32_t)
        ScanForU32Array(data, len, base,
                        kSha256K.data(), kSha256K.size(),
                        CryptoAlgorithm::SHA256,
                        "SHA-256 round constants (K[0..63]) detected",
                        false);
    }

    // -----------------------------------------------------------------------
    // 6. SHA-1 constant detection
    // -----------------------------------------------------------------------

    void ScanForSha1Constants(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        ScanForU32Array(data, len, base,
                        kSha1Init.data(), kSha1Init.size(),
                        CryptoAlgorithm::SHA1,
                        "SHA-1 initial hash values detected",
                        false);
    }

    // -----------------------------------------------------------------------
    // 7. MD5 constant detection
    // -----------------------------------------------------------------------

    void ScanForMd5Constants(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // MD5 init values overlap with SHA-1 init values for the first 4,
        // so we need to be careful. The MD5 T table is unique.
        ScanForU32Array(data, len, base,
                        kMd5T.data(), kMd5T.size(),
                        CryptoAlgorithm::MD5,
                        "MD5 T table (sine-derived round constants) detected",
                        false);

        // Also scan for MD5 init values — only flag if T table not already found nearby
        ScanForU32Array(data, len, base,
                        kMd5Init.data(), kMd5Init.size(),
                        CryptoAlgorithm::MD5,
                        "MD5 initial hash values detected",
                        false);
    }

    // -----------------------------------------------------------------------
    // Generic uint32_t array scanner (both LE and BE byte orders)
    // -----------------------------------------------------------------------

    void ScanForU32Array(
        const uint8_t* data, size_t len, GuestAddress base,
        const uint32_t* refValues, size_t refCount,
        CryptoAlgorithm algo, const char* description,
        bool isEncryption) noexcept
    {
        const size_t byteLen = refCount * sizeof(uint32_t);
        if (len < byteLen) return;

        // Build LE and BE reference buffers
        std::vector<uint8_t> refLE(byteLen);
        std::vector<uint8_t> refBE(byteLen);

        for (size_t k = 0; k < refCount; ++k) {
            const uint32_t leVal = refValues[k];
            const uint32_t beVal = ByteSwap32(refValues[k]);
            std::memcpy(refLE.data() + k * 4, &leVal, 4);
            std::memcpy(refBE.data() + k * 4, &beVal, 4);
        }

        const size_t searchEnd = len - byteLen;

        // Scan for little-endian match
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, refLE.data(), byteLen) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = algo;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(byteLen);
                f.confidence   = ConfidenceForAlgorithm(algo);
                f.description  = std::string(description) + " (little-endian)";
                f.isEncryption = isEncryption;
                AddFinding(std::move(f));
                i += byteLen - 1;
            }
        }

        // Scan for big-endian match
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, refBE.data(), byteLen) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = algo;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(byteLen);
                f.confidence   = ConfidenceForAlgorithm(algo);
                f.description  = std::string(description) + " (big-endian)";
                f.isEncryption = isEncryption;
                AddFinding(std::move(f));
                i += byteLen - 1;
            }
        }
    }

    [[nodiscard]] static float ConfidenceForAlgorithm(CryptoAlgorithm algo) noexcept {
        switch (algo) {
            case CryptoAlgorithm::SHA256:           return kConfidenceSHA256;
            case CryptoAlgorithm::SHA1:             return kConfidenceSHA1;
            case CryptoAlgorithm::MD5:              return kConfidenceMD5;
            case CryptoAlgorithm::SHA512:           return kConfidenceSHA256;
            case CryptoAlgorithm::Twofish:          return kConfidenceTwofish;
            case CryptoAlgorithm::Serpent:          return kConfidenceSerpent;
            case CryptoAlgorithm::ECC:              return kConfidenceECC;
            case CryptoAlgorithm::Blowfish:         return kConfidenceBlowfish;
            case CryptoAlgorithm::Base64:           return kConfidenceBase64;
            case CryptoAlgorithm::Base32:           return kConfidenceBase32;
            case CryptoAlgorithm::HexEncoding:      return kConfidenceHexEncoding;
            case CryptoAlgorithm::APIHashing:       return kConfidenceAPIHashing;
            case CryptoAlgorithm::StackString:      return kConfidenceStackString;
            case CryptoAlgorithm::JunkCode:         return kConfidenceJunkCode;
            case CryptoAlgorithm::RansomwarePattern:return kConfidenceRansomware;
            default:                                return 0.85f;
        }
    }

    // -----------------------------------------------------------------------
    // 8. ChaCha20 / Salsa20 detection
    // -----------------------------------------------------------------------

    void ScanForChaCha20Salsa20(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 16) return;

        const size_t searchEnd = len - 16;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            // "expand 32-byte k"
            if (std::memcmp(data + i, kChaCha20Sigma32.data(), 16) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::ChaCha20;
                f.address      = addr;
                f.size         = 16;
                f.confidence   = kConfidenceChaCha20;
                f.description  = "ChaCha20/Salsa20 sigma constant detected: "
                                 "\"expand 32-byte k\" — 256-bit key mode";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += 15;
                continue;
            }

            // "expand 16-byte k"
            if (std::memcmp(data + i, kChaCha20Sigma16.data(), 16) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::ChaCha20;
                f.address      = addr;
                f.size         = 16;
                f.confidence   = kConfidenceChaCha20;
                f.description  = "ChaCha20/Salsa20 sigma constant detected: "
                                 "\"expand 16-byte k\" — 128-bit key mode";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += 15;
                continue;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 9. CRC32 table detection
    // -----------------------------------------------------------------------

    void ScanForCrc32Table(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // We need at least 32 consecutive CRC32 table entries (32 × 4 = 128 bytes)
        static constexpr size_t kMinCrc32Entries = 32;
        static constexpr size_t kMinCrc32Bytes   = kMinCrc32Entries * sizeof(uint32_t);

        if (len < kMinCrc32Bytes) return;

        const size_t searchEnd = len - kMinCrc32Bytes;
        for (size_t i = 0; i <= searchEnd; i += 4) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            // Check for consecutive CRC32 entries in LE order (native x86)
            uint32_t matchCount = 0;
            for (uint32_t entry = 0; entry < 256 && (i + (entry + 1) * 4) <= len; ++entry) {
                const uint32_t val = ReadU32LE(data + i + entry * 4);
                if (val == kCrc32Table[entry]) {
                    ++matchCount;
                } else {
                    break;
                }
            }

            if (matchCount >= kMinCrc32Entries) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::CRC32;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(matchCount) * sizeof(uint32_t);
                f.confidence   = kConfidenceCRC32;
                f.isEncryption = false;

                if (matchCount == 256) {
                    f.description = "Complete CRC32 lookup table detected (polynomial 0xEDB88320, 256 entries)";
                } else {
                    f.description = "Partial CRC32 lookup table detected (" +
                                    std::to_string(matchCount) +
                                    " of 256 entries, polynomial 0xEDB88320)";
                }

                AddFinding(std::move(f));
                i += matchCount * 4 - 4;
                continue;
            }

            // Also check BE order for platforms that store tables big-endian
            matchCount = 0;
            for (uint32_t entry = 0; entry < 256 && (i + (entry + 1) * 4) <= len; ++entry) {
                const uint32_t val = ReadU32BE(data + i + entry * 4);
                if (val == kCrc32Table[entry]) {
                    ++matchCount;
                } else {
                    break;
                }
            }

            if (matchCount >= kMinCrc32Entries) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::CRC32;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(matchCount) * sizeof(uint32_t);
                f.confidence   = kConfidenceCRC32;
                f.isEncryption = false;
                f.description  = "CRC32 lookup table detected (big-endian byte order, " +
                                 std::to_string(matchCount) + " entries)";
                AddFinding(std::move(f));
                i += matchCount * 4 - 4;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 10. Blowfish P-array + S-box detection (enhanced)
    // -----------------------------------------------------------------------

    void ScanForBlowfish(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Phase 1: Scan for full 18-entry P-array (72 bytes) — high confidence
        static constexpr size_t kFullPBytes = kBlowfishPFull.size() * sizeof(uint32_t);
        if (len >= kFullPBytes) {
            ScanForBlowfishPFull(data, len, base);
        }

        // Phase 2: Scan for partial 4-entry P-array head (16 bytes) — standard confidence
        static constexpr size_t kHeadPBytes = kBlowfishPInit.size() * sizeof(uint32_t);
        if (len >= kHeadPBytes) {
            ScanForBlowfishPHead(data, len, base);
        }

        // Phase 3: Scan for S-box 0 initial values (64 bytes) — confirms Blowfish
        static constexpr size_t kS0HeadBytes = kBlowfishS0Head.size() * sizeof(uint32_t);
        if (len >= kS0HeadBytes) {
            ScanForBlowfishSBox(data, len, base);
        }
    }

    void ScanForBlowfishPFull(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        static constexpr size_t kBytes = kBlowfishPFull.size() * sizeof(uint32_t);

        std::array<uint8_t, kBytes> refLE{};
        std::array<uint8_t, kBytes> refBE{};
        for (size_t k = 0; k < kBlowfishPFull.size(); ++k) {
            const uint32_t leVal = kBlowfishPFull[k];
            const uint32_t beVal = ByteSwap32(kBlowfishPFull[k]);
            std::memcpy(refLE.data() + k * 4, &leVal, 4);
            std::memcpy(refBE.data() + k * 4, &beVal, 4);
        }

        const size_t searchEnd = len - kBytes;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            bool matchLE = (std::memcmp(data + i, refLE.data(), kBytes) == 0);
            bool matchBE = (std::memcmp(data + i, refBE.data(), kBytes) == 0);

            if (matchLE || matchBE) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Blowfish;
                f.address      = addr;
                f.size         = kBytes;
                f.confidence   = kConfidenceBlowfishFull;
                f.description  = matchLE
                    ? "Blowfish full P-array detected (18 entries, little-endian) "
                      "— indicates key schedule initialization"
                    : "Blowfish full P-array detected (18 entries, big-endian) "
                      "— indicates key schedule initialization";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += kBytes - 1;
            }
        }
    }

    void ScanForBlowfishPHead(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        static constexpr size_t kBytes = kBlowfishPInit.size() * sizeof(uint32_t);

        std::array<uint8_t, kBytes> refLE{};
        std::array<uint8_t, kBytes> refBE{};
        for (size_t k = 0; k < kBlowfishPInit.size(); ++k) {
            const uint32_t leVal = kBlowfishPInit[k];
            const uint32_t beVal = ByteSwap32(kBlowfishPInit[k]);
            std::memcpy(refLE.data() + k * 4, &leVal, 4);
            std::memcpy(refBE.data() + k * 4, &beVal, 4);
        }

        const size_t searchEnd = len - kBytes;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            bool matchLE = (std::memcmp(data + i, refLE.data(), kBytes) == 0);
            bool matchBE = (std::memcmp(data + i, refBE.data(), kBytes) == 0);

            if (matchLE || matchBE) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Blowfish;
                f.address      = addr;
                f.size         = kBytes;
                f.confidence   = kConfidenceBlowfish;
                f.description  = matchLE
                    ? "Blowfish P-array initial values detected (little-endian)"
                    : "Blowfish P-array initial values detected (big-endian)";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += kBytes - 1;
            }
        }
    }

    void ScanForBlowfishSBox(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        static constexpr size_t kBytes = kBlowfishS0Head.size() * sizeof(uint32_t);

        std::array<uint8_t, kBytes> refLE{};
        std::array<uint8_t, kBytes> refBE{};
        for (size_t k = 0; k < kBlowfishS0Head.size(); ++k) {
            const uint32_t leVal = kBlowfishS0Head[k];
            const uint32_t beVal = ByteSwap32(kBlowfishS0Head[k]);
            std::memcpy(refLE.data() + k * 4, &leVal, 4);
            std::memcpy(refBE.data() + k * 4, &beVal, 4);
        }

        const size_t searchEnd = len - kBytes;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            bool matchLE = (std::memcmp(data + i, refLE.data(), kBytes) == 0);
            bool matchBE = (std::memcmp(data + i, refBE.data(), kBytes) == 0);

            if (matchLE || matchBE) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Blowfish;
                f.address      = addr;
                f.size         = kBytes;
                f.confidence   = kConfidenceBlowfishFull;
                f.description  = "Blowfish S-box 0 initial values detected "
                                 "— confirms Blowfish key schedule present in memory";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += kBytes - 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 11. RSA ASN.1 header detection
    // -----------------------------------------------------------------------

    void ScanForRSAHeaders(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 16) return;

        const size_t searchEnd = len - 16;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            // Pattern 1: SEQUENCE (0x30 0x82) followed by rsaEncryption OID
            if (data[i] == 0x30 && data[i + 1] == 0x82) {
                // Check if rsaEncryption OID appears within the next ~32 bytes
                const size_t oidSearchEnd = std::min(i + 32, len - kRsaOidHeader.size());
                for (size_t j = i + 4; j <= oidSearchEnd; ++j) {
                    if (std::memcmp(data + j, kRsaOidHeader.data(),
                                    kRsaOidHeader.size()) == 0) {
                        MarkFlagged(addr);
                        // Extract approximate key size from SEQUENCE length
                        uint16_t seqLen = static_cast<uint16_t>(
                            (data[i + 2] << 8) | data[i + 3]);
                        uint32_t keyBits = (seqLen > 128) ? (seqLen - 26) * 8 : 0;

                        CryptoFinding f;
                        f.algorithm    = CryptoAlgorithm::RSA;
                        f.address      = addr;
                        f.size         = static_cast<GuestSize>(seqLen) + 4;
                        f.confidence   = kConfidenceRSA;
                        f.isEncryption = true;

                        if (keyBits >= 512) {
                            f.description = "RSA public key structure detected "
                                            "(ASN.1 DER, ~" +
                                            std::to_string(keyBits) + "-bit)";
                        } else {
                            f.description = "RSA public key structure detected (ASN.1 DER)";
                        }

                        AddFinding(std::move(f));
                        i = j + kRsaOidHeader.size() - 1;
                        goto next_rsa_outer;
                    }
                }
            }

            // Pattern 2: PKCS#8 private key: 30 82 XX XX 02 01 00
            if (data[i] == 0x30 && data[i + 1] == 0x82 && (i + 6) < len) {
                if (data[i + 4] == kRsaPkcs8Prefix[0] &&
                    data[i + 5] == kRsaPkcs8Prefix[1] &&
                    data[i + 6] == kRsaPkcs8Prefix[2]) {
                    // Verify the OID follows somewhere nearby
                    const size_t oidSearchEnd2 = std::min(i + 32, len - kRsaOidHeader.size());
                    for (size_t j = i + 7; j <= oidSearchEnd2; ++j) {
                        if (std::memcmp(data + j, kRsaOidHeader.data(),
                                        kRsaOidHeader.size()) == 0) {
                            MarkFlagged(addr);
                            uint16_t seqLen = static_cast<uint16_t>(
                                (data[i + 2] << 8) | data[i + 3]);

                            CryptoFinding f;
                            f.algorithm    = CryptoAlgorithm::RSA;
                            f.address      = addr;
                            f.size         = static_cast<GuestSize>(seqLen) + 4;
                            f.confidence   = kConfidenceRSA;
                            f.description  = "RSA private key structure detected (PKCS#8 ASN.1 DER)";
                            f.isEncryption = false;
                            AddFinding(std::move(f));
                            i = j + kRsaOidHeader.size() - 1;
                            goto next_rsa_outer;
                        }
                    }
                }
            }
            next_rsa_outer:;
        }
    }

    // -----------------------------------------------------------------------
    // 12. Twofish detection
    // -----------------------------------------------------------------------

    void ScanForTwofish(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        ScanForTwofishQTables(data, len, base);
        ScanForTwofishMDS(data, len, base);
        ScanForTwofishRS(data, len, base);
    }

    void ScanForTwofishQTables(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < kTwofishQ0Head.size()) return;

        const size_t searchEnd = len - kTwofishQ0Head.size();
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, kTwofishQ0Head.data(), kTwofishQ0Head.size()) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Twofish;
                f.address      = addr;
                f.size         = 256; // Full Q0 table is 256 bytes
                f.confidence   = kConfidenceTwofish;
                f.description  = "Twofish Q0 permutation table detected "
                                 "— key-dependent S-box construction";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += kTwofishQ0Head.size() - 1;
                continue;
            }

            if (std::memcmp(data + i, kTwofishQ1Head.data(), kTwofishQ1Head.size()) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Twofish;
                f.address      = addr;
                f.size         = 256;
                f.confidence   = kConfidenceTwofish;
                f.description  = "Twofish Q1 permutation table detected "
                                 "— key-dependent S-box construction";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += kTwofishQ1Head.size() - 1;
                continue;
            }
        }
    }

    void ScanForTwofishMDS(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < kTwofishMDS.size()) return;

        const size_t searchEnd = len - kTwofishMDS.size();
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, kTwofishMDS.data(), kTwofishMDS.size()) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Twofish;
                f.address      = addr;
                f.size         = kTwofishMDS.size();
                f.confidence   = kConfidenceTwofish * 0.9f;
                f.description  = "Twofish MDS matrix constants detected";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += kTwofishMDS.size() - 1;
            }
        }
    }

    void ScanForTwofishRS(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < kTwofishRS.size()) return;

        const size_t searchEnd = len - kTwofishRS.size();
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, kTwofishRS.data(), kTwofishRS.size()) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Twofish;
                f.address      = addr;
                f.size         = kTwofishRS.size();
                f.confidence   = kConfidenceTwofish;
                f.description  = "Twofish Reed-Solomon matrix detected "
                                 "— key-dependent S-box generation";
                f.isEncryption = true;
                AddFinding(std::move(f));
                i += kTwofishRS.size() - 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 13. Serpent detection
    // -----------------------------------------------------------------------

    void ScanForSerpent(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        ScanForSerpentSboxes(data, len, base);
        ScanForSerpentPhi(data, len, base);
    }

    void ScanForSerpentSboxes(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Each Serpent S-box is 16 bytes (values 0–15). Require at least 4
        // consecutive S-boxes (64 bytes) to avoid false positives on small nibble tables.
        static constexpr size_t kSingleSboxLen = 16;
        static constexpr uint32_t kMinConsecutive = 4;
        static constexpr size_t kMinMatchBytes = kSingleSboxLen * kMinConsecutive;
        if (len < kMinMatchBytes) return;

        const size_t searchEnd = len - kSingleSboxLen;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            // Try to match the first S-box at this offset
            uint32_t consecutiveMatched = 0;
            for (uint32_t sboxIdx = 0; sboxIdx < 8; ++sboxIdx) {
                const size_t offset = i + static_cast<size_t>(sboxIdx) * kSingleSboxLen;
                if (offset + kSingleSboxLen > len) break;

                if (std::memcmp(data + offset,
                                kSerpentSboxes[sboxIdx].data(),
                                kSingleSboxLen) == 0) {
                    ++consecutiveMatched;
                } else {
                    break;
                }
            }

            if (consecutiveMatched >= kMinConsecutive) {
                MarkFlagged(addr);
                const size_t matchSize = static_cast<size_t>(consecutiveMatched) * kSingleSboxLen;

                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Serpent;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(matchSize);
                f.isEncryption = true;

                if (consecutiveMatched == 8) {
                    f.confidence  = kConfidenceSerpent;
                    f.description = "Complete Serpent S-box array detected (all 8 S-boxes)";
                } else {
                    f.confidence  = kConfidenceSerpent * 0.85f;
                    f.description = "Serpent S-box block detected (" +
                                    std::to_string(consecutiveMatched) +
                                    " of 8 consecutive S-boxes)";
                }

                AddFinding(std::move(f));
                i += matchSize - 1;
            }
        }
    }

    void ScanForSerpentPhi(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Serpent uses phi = 0x9E3779B9 as a round constant in key schedule.
        // This constant is also used by TEA/XTEA, so we flag with moderate confidence.
        if (len < 4) return;

        const uint32_t phiLE = kSerpentPhi;
        const uint32_t phiBE = ByteSwap32(kSerpentPhi);

        const size_t searchEnd = len - 4;
        uint32_t phiCount = 0;
        GuestAddress firstAddr = 0;

        for (size_t i = 0; i <= searchEnd; i += 4) {
            const uint32_t val = ReadU32LE(data + i);
            if (val == phiLE || val == phiBE) {
                if (phiCount == 0) {
                    firstAddr = base + static_cast<GuestAddress>(i);
                }
                ++phiCount;
            }
        }

        // Serpent key schedule uses phi in 132 subkey derivations.
        // Finding multiple instances strongly suggests Serpent or TEA-family.
        if (phiCount >= 4 && !IsAlreadyFlagged(firstAddr)) {
            MarkFlagged(firstAddr);
            CryptoFinding f;
            f.algorithm    = CryptoAlgorithm::Serpent;
            f.address      = firstAddr;
            f.size         = 4;
            f.confidence   = kConfidenceSerpent * 0.7f;
            f.description  = "Golden ratio constant 0x9E3779B9 found " +
                             std::to_string(phiCount) +
                             " times — Serpent/TEA key schedule indicator";
            f.isEncryption = true;
            AddFinding(std::move(f));
        }
    }

    // -----------------------------------------------------------------------
    // 14. Elliptic Curve (ECDSA/ECDH) constant detection
    // -----------------------------------------------------------------------

    void ScanForECCConstants(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < 32) return;

        struct ECCConstant {
            const uint8_t* data;
            size_t         size;
            const char*    curveName;
            const char*    pointName;
        };

        const ECCConstant kECCConstants[] = {
            { kSecp256k1Gx.data(), kSecp256k1Gx.size(), "secp256k1", "Gx" },
            { kSecp256k1Gy.data(), kSecp256k1Gy.size(), "secp256k1", "Gy" },
            { kP256Gx.data(),      kP256Gx.size(),      "P-256",     "Gx" },
            { kP256Gy.data(),      kP256Gy.size(),      "P-256",     "Gy" },
            { kP256Order.data(),   kP256Order.size(),    "P-256",     "order n" },
            { kCurve25519Prime.data(), kCurve25519Prime.size(),
              "Curve25519", "prime p=2^255-19" },
        };

        for (const auto& ecc : kECCConstants) {
            if (len < ecc.size) continue;
            const size_t searchEnd = len - ecc.size;

            for (size_t i = 0; i <= searchEnd; ++i) {
                const GuestAddress addr = base + static_cast<GuestAddress>(i);
                if (IsAlreadyFlagged(addr)) continue;

                if (std::memcmp(data + i, ecc.data, ecc.size) == 0) {
                    MarkFlagged(addr);
                    CryptoFinding f;
                    f.algorithm    = CryptoAlgorithm::ECC;
                    f.address      = addr;
                    f.size         = static_cast<GuestSize>(ecc.size);
                    f.confidence   = kConfidenceECC;
                    f.description  = std::string("Elliptic curve constant detected: ") +
                                     ecc.curveName + " " + ecc.pointName +
                                     " — ECDSA/ECDH key exchange indicator";
                    f.isEncryption = true;
                    AddFinding(std::move(f));
                    i += ecc.size - 1;
                    break; // One match per constant per scan pass
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 15. Base64 / Base32 / Hex encoding table detection
    // -----------------------------------------------------------------------

    void ScanForEncodingTables(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        ScanForBase64Table(data, len, base);
        ScanForBase32Table(data, len, base);
        ScanForHexTable(data, len, base);
    }

    void ScanForBase64Table(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < kBase64Alphabet.size()) return;

        const size_t searchEnd = len - kBase64Alphabet.size();
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            // Standard Base64 alphabet match
            if (std::memcmp(data + i, kBase64Alphabet.data(),
                            kBase64Alphabet.size()) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Base64;
                f.address      = addr;
                f.size         = kBase64Alphabet.size();
                f.confidence   = kConfidenceBase64;
                f.description  = "Standard Base64 encoding alphabet detected "
                                 "— data obfuscation/exfiltration indicator";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i += kBase64Alphabet.size() - 1;
                continue;
            }

            // Custom Base64 alphabet heuristic: 64 consecutive printable ASCII chars
            // where each char is unique and the set covers [A-Z], [a-z], [0-9]
            if (IsCustomBase64Alphabet(data + i, len - i)) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Base64;
                f.address      = addr;
                f.size         = 64;
                f.confidence   = kConfidenceBase64 * 0.75f;
                f.description  = "Possible custom Base64 alphabet detected (64 unique "
                                 "printable chars spanning alphanumeric ranges)";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i += 63;
            }
        }
    }

    [[nodiscard]] static bool IsCustomBase64Alphabet(
        const uint8_t* data, size_t available) noexcept
    {
        if (available < 64) return false;

        std::array<bool, 256> seen{};
        bool hasUpper = false, hasLower = false, hasDigit = false;
        uint32_t uniqueCount = 0;

        for (size_t j = 0; j < 64; ++j) {
            const uint8_t c = data[j];
            // Must be printable ASCII (0x21–0x7E, excluding space)
            if (c < 0x21 || c > 0x7E) return false;
            if (seen[c]) return false; // Duplicates → not an alphabet
            seen[c] = true;
            ++uniqueCount;

            if (c >= 'A' && c <= 'Z') hasUpper = true;
            if (c >= 'a' && c <= 'z') hasLower = true;
            if (c >= '0' && c <= '9') hasDigit = true;
        }

        // A genuine Base64 alphabet spans uppercase, lowercase, and digits
        return uniqueCount == 64 && hasUpper && hasLower && hasDigit;
    }

    void ScanForBase32Table(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < kBase32Alphabet.size()) return;

        const size_t searchEnd = len - kBase32Alphabet.size();
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            if (std::memcmp(data + i, kBase32Alphabet.data(),
                            kBase32Alphabet.size()) == 0) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::Base32;
                f.address      = addr;
                f.size         = kBase32Alphabet.size();
                f.confidence   = kConfidenceBase32;
                f.description  = "Base32 encoding alphabet detected (RFC 4648)";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i += kBase32Alphabet.size() - 1;
            }
        }
    }

    void ScanForHexTable(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < kHexAlphabetLower.size()) return;

        const size_t searchEnd = len - kHexAlphabetLower.size();
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            bool matchLower = (std::memcmp(data + i, kHexAlphabetLower.data(),
                                           kHexAlphabetLower.size()) == 0);
            bool matchUpper = (std::memcmp(data + i, kHexAlphabetUpper.data(),
                                           kHexAlphabetUpper.size()) == 0);

            if (matchLower || matchUpper) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::HexEncoding;
                f.address      = addr;
                f.size         = kHexAlphabetLower.size();
                f.confidence   = kConfidenceHexEncoding;
                f.description  = matchLower
                    ? "Hex encoding lookup table detected (lowercase 0-9a-f)"
                    : "Hex encoding lookup table detected (uppercase 0-9A-F)";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i += kHexAlphabetLower.size() - 1;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 16. API hash constant detection
    // -----------------------------------------------------------------------

    void ScanForAPIHashes(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Scan for known API hash constants in memory. Shellcode and packers
        // embed these as immediate operands or in lookup tables.
        // Require a cluster of 2+ known hashes within 256 bytes to reduce FP.
        if (len < 4) return;

        struct HashHit {
            size_t      offset;
            size_t      entryIdx;
        };

        // Cap the number of hash hits we track to prevent excessive processing
        static constexpr size_t kMaxHashHits = 1024;
        std::vector<HashHit> hits;
        hits.reserve(128);

        const size_t searchEnd = len - 4;
        for (size_t i = 0; i <= searchEnd && hits.size() < kMaxHashHits; i += 1) {
            const uint32_t valLE = ReadU32LE(data + i);

            for (size_t k = 0; k < kKnownAPIHashCount; ++k) {
                if (valLE == kKnownAPIHashes[k].hash) {
                    hits.push_back({ i, k });
                    break;
                }
            }
        }

        if (hits.size() < kMinAPIHashCluster) return;

        // Cluster hits: find groups within 256-byte windows
        for (size_t h = 0; h < hits.size(); ++h) {
            const GuestAddress addr = base + static_cast<GuestAddress>(hits[h].offset);
            if (IsAlreadyFlagged(addr)) continue;

            uint32_t clusterCount = 1;
            size_t clusterEnd = h;

            for (size_t j = h + 1; j < hits.size(); ++j) {
                if (hits[j].offset - hits[h].offset <= 256) {
                    ++clusterCount;
                    clusterEnd = j;
                } else {
                    break;
                }
            }

            if (clusterCount >= kMinAPIHashCluster) {
                MarkFlagged(addr);

                const auto& firstEntry = kKnownAPIHashes[hits[h].entryIdx];
                const auto& lastEntry  = kKnownAPIHashes[hits[clusterEnd].entryIdx];
                const size_t spanBytes = hits[clusterEnd].offset - hits[h].offset + 4;

                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::APIHashing;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(spanBytes);
                f.confidence   = kConfidenceAPIHashing;
                f.isEncryption = false;
                f.description  = "API hash resolution detected: " +
                                 std::to_string(clusterCount) + " known " +
                                 std::string(firstEntry.hashAlgorithm) +
                                 " hashes (e.g., " + firstEntry.apiName;
                if (clusterCount > 1) {
                    f.description += ", " + std::string(lastEntry.apiName);
                }
                f.description += ") — shellcode/packer import resolution";

                AddFinding(std::move(f));
                h = clusterEnd; // Skip past cluster
            }
        }
    }

    // -----------------------------------------------------------------------
    // 17. Code obfuscation pattern detection
    // -----------------------------------------------------------------------

    void ScanForObfuscationPatterns(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        ScanForNOPSleds(data, len, base);
        ScanForStackStrings(data, len, base);
        ScanForJunkCodePatterns(data, len, base);
    }

    void ScanForNOPSleds(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Detect NOP sleds: 32+ consecutive 0x90 bytes
        static constexpr size_t kMinNOPSled = 32;
        if (len < kMinNOPSled) return;

        size_t runStart = 0;
        size_t runLen   = 0;
        bool   inRun    = false;

        for (size_t i = 0; i < len; ++i) {
            if (data[i] == 0x90) {
                if (!inRun) {
                    runStart = i;
                    runLen = 0;
                    inRun = true;
                }
                ++runLen;
            } else {
                if (inRun && runLen >= kMinNOPSled) {
                    const GuestAddress addr = base + static_cast<GuestAddress>(runStart);
                    if (!IsAlreadyFlagged(addr)) {
                        MarkFlagged(addr);
                        CryptoFinding f;
                        f.algorithm    = CryptoAlgorithm::JunkCode;
                        f.address      = addr;
                        f.size         = static_cast<GuestSize>(runLen);
                        f.confidence   = kConfidenceJunkCode;
                        f.description  = "NOP sled detected (" +
                                         std::to_string(runLen) +
                                         " bytes) — shellcode landing pad or code obfuscation";
                        f.isEncryption = false;
                        AddFinding(std::move(f));
                    }
                }
                inRun = false;
                runLen = 0;
            }
        }

        // Handle run at end of buffer
        if (inRun && runLen >= kMinNOPSled) {
            const GuestAddress addr = base + static_cast<GuestAddress>(runStart);
            if (!IsAlreadyFlagged(addr)) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::JunkCode;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(runLen);
                f.confidence   = kConfidenceJunkCode;
                f.description  = "NOP sled detected (" +
                                 std::to_string(runLen) +
                                 " bytes) — shellcode landing pad or code obfuscation";
                f.isEncryption = false;
                AddFinding(std::move(f));
            }
        }
    }

    void ScanForStackStrings(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Detect stack string construction:
        // Sequences of MOV [RSP+disp8], imm8 (opcode: C6 44 24 XX YY)
        // or MOV [RBP-disp8], imm8 (opcode: C6 45 XX YY)
        // occurring 6+ times within 64 bytes → building a string on the stack
        static constexpr size_t  kMinStackMoves = 6;
        static constexpr size_t  kWindowSize    = 64;
        static constexpr uint8_t kMovByteRspOp  = 0xC6; // MOV r/m8, imm8

        if (len < kWindowSize) return;

        const size_t searchEnd = len - kWindowSize;
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            uint32_t stackMoveCount = 0;
            size_t   windowEnd = std::min(i + kWindowSize, len);

            for (size_t j = i; j + 4 < windowEnd; ++j) {
                // MOV byte ptr [RSP+disp8], imm8: C6 44 24 XX YY
                if (data[j] == kMovByteRspOp && data[j + 1] == 0x44 &&
                    data[j + 2] == 0x24) {
                    const uint8_t immVal = data[j + 4];
                    // The immediate should be a printable ASCII character
                    if (immVal >= 0x20 && immVal < 0x7F) {
                        ++stackMoveCount;
                    }
                    j += 4; // Skip past this instruction
                    continue;
                }
                // MOV byte ptr [RBP+disp8], imm8: C6 45 XX YY
                if (data[j] == kMovByteRspOp && data[j + 1] == 0x45) {
                    const uint8_t immVal = data[j + 3];
                    if (immVal >= 0x20 && immVal < 0x7F) {
                        ++stackMoveCount;
                    }
                    j += 3;
                    continue;
                }
            }

            if (stackMoveCount >= kMinStackMoves) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::StackString;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(kWindowSize);
                f.confidence   = kConfidenceStackString;
                f.description  = "Stack string construction detected (" +
                                 std::to_string(stackMoveCount) +
                                 " MOV byte [RSP/RBP+X], imm8 instructions) "
                                 "— anti-analysis string obfuscation";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i += kWindowSize - 1;
            }
        }
    }

    void ScanForJunkCodePatterns(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        // Detect junk code insertion patterns:
        // 1. PUSH reg / POP same reg sequences (4+ consecutive pairs)
        // 2. MOV reg, reg (self-move) sequences
        static constexpr size_t kMinJunkPairs = 4;
        if (len < kMinJunkPairs * 2) return;

        const size_t searchEnd = len - (kMinJunkPairs * 2);
        for (size_t i = 0; i <= searchEnd; ++i) {
            const GuestAddress addr = base + static_cast<GuestAddress>(i);
            if (IsAlreadyFlagged(addr)) continue;

            // Pattern 1: PUSH reg (50-57) followed by POP same reg (58-5F)
            uint32_t pushPopPairs = 0;
            size_t scanPos = i;
            while (scanPos + 1 < len) {
                const uint8_t pushByte = data[scanPos];
                const uint8_t popByte  = data[scanPos + 1];
                // PUSH reg: 0x50-0x57 → POP same reg: 0x58-0x5F (diff = 8)
                if (pushByte >= 0x50 && pushByte <= 0x57 &&
                    popByte == pushByte + 8) {
                    ++pushPopPairs;
                    scanPos += 2;
                } else {
                    break;
                }
            }

            if (pushPopPairs >= kMinJunkPairs) {
                MarkFlagged(addr);
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::JunkCode;
                f.address      = addr;
                f.size         = static_cast<GuestSize>(pushPopPairs * 2);
                f.confidence   = kConfidenceJunkCode;
                f.description  = "Junk code detected: " +
                                 std::to_string(pushPopPairs) +
                                 " consecutive PUSH/POP register pairs "
                                 "— packer/crypter obfuscation";
                f.isEncryption = false;
                AddFinding(std::move(f));
                i = scanPos - 1;
                continue;
            }

            // Pattern 2: Multi-byte NOP (0F 1F 00, 0F 1F 40 00, etc.)
            if (i + 2 < len && data[i] == 0x0F && data[i + 1] == 0x1F) {
                size_t nopLen = 0;
                size_t pos = i;
                while (pos + 2 < len && data[pos] == 0x0F && data[pos + 1] == 0x1F) {
                    // Multi-byte NOP: 0F 1F /0 (3–9 bytes)
                    if (data[pos + 2] == 0x00) {
                        nopLen += 3;
                        pos += 3;
                    } else if (data[pos + 2] == 0x40 && pos + 3 < len) {
                        nopLen += 4;
                        pos += 4;
                    } else if (data[pos + 2] == 0x44 && pos + 4 < len) {
                        nopLen += 5;
                        pos += 5;
                    } else if (data[pos + 2] == 0x80 && pos + 6 < len) {
                        nopLen += 7;
                        pos += 7;
                    } else if (data[pos + 2] == 0x84 && pos + 7 < len) {
                        nopLen += 8;
                        pos += 8;
                    } else {
                        break;
                    }
                }

                if (nopLen >= 16) { // 16+ bytes of multi-byte NOPs
                    MarkFlagged(addr);
                    CryptoFinding f;
                    f.algorithm    = CryptoAlgorithm::JunkCode;
                    f.address      = addr;
                    f.size         = static_cast<GuestSize>(nopLen);
                    f.confidence   = kConfidenceJunkCode;
                    f.description  = "Multi-byte NOP sequence detected (" +
                                     std::to_string(nopLen) +
                                     " bytes) — code alignment or obfuscation";
                    f.isEncryption = false;
                    AddFinding(std::move(f));
                    i = pos - 1;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // 18. Custom crypto heuristic (high entropy, unknown algorithm)
    // -----------------------------------------------------------------------

    void ScanForCustomCrypto(const uint8_t* data, size_t len, GuestAddress base) noexcept {
        if (len < kMinCustomCryptoSize) return;

        // Scan in 1 KB blocks for high-entropy regions not matching known algorithms
        static constexpr size_t kBlockSize = 1024;
        const size_t blockCount = len / kBlockSize;

        for (size_t blk = 0; blk < blockCount; ++blk) {
            const size_t offset = blk * kBlockSize;
            const GuestAddress addr = base + static_cast<GuestAddress>(offset);

            if (IsAlreadyFlagged(addr)) continue;

            // Check if any finding already covers this address
            bool alreadyCovered = false;
            for (const auto& f : findings) {
                if (addr >= f.address && addr < f.address + f.size) {
                    alreadyCovered = true;
                    break;
                }
            }
            if (alreadyCovered) continue;

            const double entropy = ComputeShannonEntropy(data + offset, kBlockSize);
            if (entropy <= kHighEntropyThreshold) continue;

            // Check byte distribution for uniformity (crypto output is near-uniform)
            if (!HasUniformDistribution(data + offset, kBlockSize)) continue;

            // Extend the high-entropy region as far as possible
            size_t regionEnd = offset + kBlockSize;
            while (regionEnd + kBlockSize <= len) {
                const double nextEntropy = ComputeShannonEntropy(
                    data + regionEnd, kBlockSize);
                if (nextEntropy <= kHighEntropyThreshold) break;
                regionEnd += kBlockSize;
            }

            const size_t regionSize = regionEnd - offset;
            if (regionSize < kMinCustomCryptoSize) continue;

            MarkFlagged(addr);
            CryptoFinding f;
            f.address      = addr;
            f.size         = static_cast<GuestSize>(regionSize);
            f.confidence   = kConfidenceCustom;
            f.isEncryption = true;

            // Classify: if region size is fixed multiples of block sizes, likely block cipher
            if (regionSize % 16 == 0 || regionSize % 8 == 0) {
                f.algorithm   = CryptoAlgorithm::CustomSymmetric;
                f.description = "High-entropy region (" +
                                std::to_string(regionSize) +
                                " bytes, entropy=" +
                                FormatFloat(entropy) +
                                ") — possible custom/unknown symmetric encryption";
            } else {
                // Could be a hash output or stream cipher output
                f.algorithm   = CryptoAlgorithm::CustomHash;
                f.description = "High-entropy region (" +
                                std::to_string(regionSize) +
                                " bytes, entropy=" +
                                FormatFloat(entropy) +
                                ") — possible custom/unknown hash or stream cipher output";
            }

            AddFinding(std::move(f));

            // Skip past this region
            blk = (regionEnd / kBlockSize);
            if (blk > 0) --blk; // loop will increment
        }
    }

    [[nodiscard]] static bool HasUniformDistribution(
        const uint8_t* data, size_t size) noexcept
    {
        // Chi-squared test against uniform distribution
        std::array<uint32_t, 256> freq{};
        for (size_t i = 0; i < size; ++i) {
            ++freq[data[i]];
        }

        const double expected = static_cast<double>(size) / 256.0;
        double chiSquared = 0.0;
        for (uint32_t count : freq) {
            const double diff = static_cast<double>(count) - expected;
            chiSquared += (diff * diff) / expected;
        }

        // Critical value for chi-squared with 255 df at p=0.01 is ~310
        // High-quality crypto output should have chi-squared < 310
        return chiSquared < 400.0;
    }

    [[nodiscard]] static std::string FormatFloat(double val) noexcept {
        // Format to 2 decimal places without <format> header
        char buf[32];
        int written = std::snprintf(buf, sizeof(buf), "%.2f", val);
        if (written > 0 && written < static_cast<int>(sizeof(buf))) {
            return std::string(buf, static_cast<size_t>(written));
        }
        return "?";
    }

    // -----------------------------------------------------------------------
    // XOR loop analysis (called from OnXOROperation)
    // -----------------------------------------------------------------------

    void ProcessXorOperation(
        GuestAddress rip, uint8_t key,
        GuestAddress dataAddr, uint32_t size) noexcept
    {
        if (key == 0) return; // XOR with 0 is a NOP (register zeroing)

        std::unique_lock lock(mutex);

        if (xorRecords.size() >= kMaxXorRecords && xorRecords.count(rip) == 0) {
            return; // Cap reached, ignore new RIPs
        }

        auto& rec = xorRecords[rip];
        if (rec.hitCount == 0) {
            rec.key           = key;
            rec.firstDataAddr = dataAddr;
            rec.lastDataAddr  = dataAddr;
            rec.lastOpSize    = size;
        } else {
            rec.lastDataAddr = dataAddr;
            rec.lastOpSize   = size;
        }

        ++rec.hitCount;

        // Check for key change (multi-byte XOR pattern)
        const bool keyChanged = (rec.key != key);
        if (keyChanged && rec.hitCount > 1) {
            // This instruction uses different keys — multi-byte XOR
            CheckAndEmitXorFinding(rip, rec, true);
            return;
        }

        // Check threshold for single-byte XOR loop
        if (rec.hitCount >= kXorLoopThreshold && rec.key == key) {
            // Verify sequential data addresses (loop pattern)
            if (IsSequentialXorRange(rec)) {
                CheckAndEmitXorFinding(rip, rec, false);
            }
        }
    }

    [[nodiscard]] bool IsSequentialXorRange(const XorOpRecord& rec) const noexcept {
        if (rec.firstDataAddr == 0 || rec.lastDataAddr == 0) return false;
        // The range should be roughly hitCount * opSize
        const GuestAddress expectedRange =
            static_cast<GuestAddress>(rec.hitCount) * rec.lastOpSize;
        const GuestAddress actualRange =
            (rec.lastDataAddr > rec.firstDataAddr)
                ? (rec.lastDataAddr - rec.firstDataAddr + rec.lastOpSize)
                : (rec.firstDataAddr - rec.lastDataAddr + rec.lastOpSize);
        // Allow 50% tolerance for non-contiguous access patterns
        return actualRange <= expectedRange * 2;
    }

    void CheckAndEmitXorFinding(
        GuestAddress rip, const XorOpRecord& rec, bool isMultiKey) noexcept
    {
        if (IsAlreadyFlagged(rip)) return;
        MarkFlagged(rip);

        const GuestAddress rangeStart = std::min(rec.firstDataAddr, rec.lastDataAddr);
        const GuestAddress rangeEnd   = std::max(rec.firstDataAddr, rec.lastDataAddr) + rec.lastOpSize;

        CryptoFinding f;
        f.address      = rangeStart;
        f.size         = rangeEnd - rangeStart;
        f.isEncryption = true;

        if (isMultiKey) {
            f.algorithm   = CryptoAlgorithm::XOR_Multi;
            f.confidence  = kConfidenceXorMulti;
            f.description = "XOR encryption loop detected at RIP=0x" +
                            ToHex64(rip) + " — multi-byte key pattern, " +
                            std::to_string(rec.hitCount) + " iterations over " +
                            std::to_string(f.size) + " bytes";
        } else {
            f.algorithm   = CryptoAlgorithm::XOR_Single;
            f.confidence  = kConfidenceXorSingle;
            f.description = "XOR encryption loop detected at RIP=0x" +
                            ToHex64(rip) + " — single-byte key 0x" +
                            ToHex8(rec.key) + ", " +
                            std::to_string(rec.hitCount) + " iterations over " +
                            std::to_string(f.size) + " bytes";
            f.keyMaterial.push_back(rec.key);
        }

        if (f.keyMaterial.size() > kMaxKeyMaterialBytes) {
            f.keyMaterial.resize(kMaxKeyMaterialBytes);
        }

        AddFinding(std::move(f));
    }

    // -----------------------------------------------------------------------
    // Crypto API call processing
    // -----------------------------------------------------------------------

    void ProcessCryptoAPICall(
        const char* funcName, const uint64_t* args) noexcept
    {
        if (!funcName) return;

        std::unique_lock lock(mutex);

        const std::string_view name(funcName);

        // Find matching API entry
        const CryptoApiEntry* matched = nullptr;
        for (size_t k = 0; k < kCryptoApiCount; ++k) {
            if (name == kCryptoApis[k].name) {
                matched = &kCryptoApis[k];
                break;
            }
        }

        if (!matched) return;

        // Record API call (capped)
        if (apiCallsSeen.size() < kMaxApiCallRecords) {
            apiCallsSeen.emplace_back(funcName);
        }

        // Only emit findings for actionable APIs
        if (matched->mappedAlgo == CryptoAlgorithm::Unknown) {
            // Context-setting API (e.g., CryptAcquireContext) — track but don't emit
            return;
        }

        // Attempt to extract algorithm from BCryptOpenAlgorithmProvider argument
        CryptoAlgorithm detectedAlgo = matched->mappedAlgo;
        bool isEncrypt = matched->isEncryption;

        if (name == "BCryptOpenAlgorithmProvider" && args) {
            // args[1] is typically the algorithm identifier string pointer
            // We can't dereference guest pointers here, so use generic classification
            detectedAlgo = CryptoAlgorithm::CustomSymmetric;
        }

        if (name == "BCryptEncrypt" || name == "CryptEncrypt") {
            isEncrypt = true;
            detectedAlgo = CryptoAlgorithm::CustomSymmetric;
        }

        if (name == "BCryptDecrypt" || name == "CryptDecrypt") {
            isEncrypt = false;
            detectedAlgo = CryptoAlgorithm::CustomSymmetric;
        }

        if (name == "CryptCreateHash") {
            detectedAlgo = CryptoAlgorithm::CustomHash;
            isEncrypt = false;
        }

        if (name == "CryptGenRandom" || name == "BCryptGenRandom") {
            // Track random number generation — precedes per-file key derivation
            // in ransomware encryption chains
            ++cryptGenRandomCount;

            // Emit ransomware pattern finding after multiple CryptGenRandom calls
            // interleaved with encryption API calls
            if (cryptGenRandomCount >= 3 && HasEncryptionAPICalls()) {
                CryptoFinding f;
                f.algorithm    = CryptoAlgorithm::RansomwarePattern;
                f.address      = 0;
                f.size         = 0;
                f.confidence   = kConfidenceRansomware;
                f.isEncryption = true;
                f.description  = "Ransomware per-file key generation pattern: " +
                                 std::to_string(cryptGenRandomCount) +
                                 " CryptGenRandom calls interleaved with encryption "
                                 "— hybrid encryption lifecycle detected";
                AddFinding(std::move(f));
            }
            return;
        }

        CryptoFinding f;
        f.algorithm    = detectedAlgo;
        f.address      = 0; // API call, no specific memory address
        f.size         = 0;
        f.confidence   = kConfidenceCryptoAPI;
        f.isEncryption = isEncrypt;
        f.description  = "Crypto API call detected: " + std::string(name);

        // Extract key handle from args if available
        if (args && (name == "BCryptGenerateSymmetricKey" ||
                     name == "CryptImportKey" ||
                     name == "CryptDeriveKey")) {
            f.description += " (key generation/import)";
        }

        AddFinding(std::move(f));
    }

    // -----------------------------------------------------------------------
    // Ransomware lifecycle helper
    // -----------------------------------------------------------------------

    [[nodiscard]] bool HasEncryptionAPICalls() const noexcept {
        for (const auto& call : apiCallsSeen) {
            if (call == "BCryptEncrypt" || call == "CryptEncrypt" ||
                call == "BCryptDecrypt" || call == "CryptDecrypt") {
                return true;
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Stats computation
    // -----------------------------------------------------------------------

    [[nodiscard]] CryptoStats ComputeStats() const noexcept {
        CryptoStats stats;
        stats.totalFindings = static_cast<uint32_t>(findings.size());

        bool hasAES        = false;
        bool hasAESInv     = false;
        bool hasRSA        = false;
        bool hasSymmetric  = false;
        bool hasECC        = false;
        bool hasEncoding   = false;
        bool hasAPIHashing = false;
        bool hasStackStr   = false;
        bool hasJunkCode   = false;

        std::unordered_set<uint8_t> algoSeen;

        for (const auto& f : findings) {
            if (f.isEncryption) {
                ++stats.encryptionCount;
            } else {
                ++stats.decryptionCount;
            }

            const auto algoVal = static_cast<uint8_t>(f.algorithm);
            if (algoSeen.insert(algoVal).second) {
                stats.algorithmsFound.push_back(f.algorithm);
            }

            switch (f.algorithm) {
                case CryptoAlgorithm::AES:
                    hasAES = true;
                    hasSymmetric = true;
                    break;
                case CryptoAlgorithm::AES_Inv:
                    hasAESInv = true;
                    hasSymmetric = true;
                    break;
                case CryptoAlgorithm::RSA:
                    hasRSA = true;
                    break;
                case CryptoAlgorithm::ECC:
                    hasECC = true;
                    break;
                case CryptoAlgorithm::Base64:
                case CryptoAlgorithm::Base32:
                case CryptoAlgorithm::HexEncoding:
                    hasEncoding = true;
                    break;
                case CryptoAlgorithm::APIHashing:
                    hasAPIHashing = true;
                    break;
                case CryptoAlgorithm::StackString:
                    hasStackStr = true;
                    break;
                case CryptoAlgorithm::JunkCode:
                    hasJunkCode = true;
                    break;
                case CryptoAlgorithm::RC4:
                case CryptoAlgorithm::XOR_Single:
                case CryptoAlgorithm::XOR_Multi:
                case CryptoAlgorithm::DES:
                case CryptoAlgorithm::TripleDES:
                case CryptoAlgorithm::ChaCha20:
                case CryptoAlgorithm::Salsa20:
                case CryptoAlgorithm::Blowfish:
                case CryptoAlgorithm::Twofish:
                case CryptoAlgorithm::Serpent:
                case CryptoAlgorithm::CustomSymmetric:
                case CryptoAlgorithm::CustomStream:
                    hasSymmetric = true;
                    break;
                default:
                    break;
            }
        }

        // Ransomware indicator: AES (encrypt or decrypt) + RSA (key exchange)
        stats.hasRansomwareIndicator = (hasAES || hasAESInv) && hasRSA;

        // C2 encryption indicator: any symmetric cipher + network activity
        stats.hasC2Encryption = hasSymmetric && hasNetworkActivity;

        // Obfuscation indicator: API hashing, stack strings, or junk code
        stats.hasObfuscationIndicator = hasAPIHashing || hasStackStr || hasJunkCode;

        // Encoding indicator: data encoding tables detected
        stats.hasEncodingIndicator = hasEncoding;

        // ECC key exchange indicator
        stats.hasECCKeyExchange = hasECC;

        // Per-file key generation count from tracked CryptGenRandom calls
        stats.perFileKeyGenCount = cryptGenRandomCount;

        return stats;
    }

    // -----------------------------------------------------------------------
    // Hex formatting helpers
    // -----------------------------------------------------------------------

    [[nodiscard]] static std::string ToHex64(uint64_t val) noexcept {
        static constexpr char kHexDigits[] = "0123456789ABCDEF";
        std::string result(16, '0');
        for (int i = 15; i >= 0; --i) {
            result[static_cast<size_t>(i)] = kHexDigits[val & 0xF];
            val >>= 4;
        }
        // Strip leading zeros but keep at least one digit
        size_t firstNonZero = result.find_first_not_of('0');
        if (firstNonZero == std::string::npos) return "0";
        return result.substr(firstNonZero);
    }

    [[nodiscard]] static std::string ToHex8(uint8_t val) noexcept {
        static constexpr char kHexDigits[] = "0123456789ABCDEF";
        std::string result(2, '0');
        result[0] = kHexDigits[(val >> 4) & 0xF];
        result[1] = kHexDigits[val & 0xF];
        return result;
    }
};

// ============================================================================
// CryptoDetector — Public API Implementation
// ============================================================================

CryptoDetector::CryptoDetector(const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>(config))
{
}

CryptoDetector::~CryptoDetector() noexcept = default;

CryptoDetector::CryptoDetector(CryptoDetector&&) noexcept = default;

CryptoDetector& CryptoDetector::operator=(CryptoDetector&&) noexcept = default;

// ============================================================================
// ScanRegion — scan a host-side buffer for crypto artefacts
// ============================================================================

void CryptoDetector::ScanRegion(
    const uint8_t* data, size_t size, GuestAddress base) noexcept
{
    if (!data || size == 0) return;
    if (!m_impl->config.enableBehaviorMonitor) return;

    std::unique_lock lock(m_impl->mutex);
    m_impl->ScanBuffer(data, size, base);
}

// ============================================================================
// ScanAll — walk all allocated guest memory pages
// ============================================================================

void CryptoDetector::ScanAll(const VirtualMemory& memory) noexcept
{
    if (!m_impl->config.enableBehaviorMonitor) return;

    const uint32_t totalPages = memory.GetAllocatedPages();
    if (totalPages == 0) return;

    // Cap scanning to prevent excessive runtime
    const uint32_t maxPages = std::min(totalPages, kMaxPagesPerScan);

    std::unique_lock lock(m_impl->mutex);

    // Scan page by page using GetHostReadPtr
    // Walk contiguous address space up to allocated bounds
    const GuestSize allocatedBytes = memory.GetAllocatedBytes();
    if (allocatedBytes == 0) return;

    // Scan in page-aligned chunks
    const GuestAddress maxAddr = std::min(allocatedBytes, kMaxScanRegionSize);
    uint32_t pagesScanned = 0;

    for (GuestAddress pageBase = 0;
         pageBase < maxAddr && pagesScanned < maxPages;
         pageBase += kPageSize) {

        const uint8_t* hostPtr = memory.GetHostReadPtr(pageBase);
        if (!hostPtr) continue;

        // Determine how many contiguous pages we can scan at once
        size_t contiguousBytes = kPageSize;
        while (pageBase + contiguousBytes < maxAddr &&
               pagesScanned + (contiguousBytes / kPageSize) < maxPages) {
            const uint8_t* nextPtr = memory.GetHostReadPtr(
                pageBase + static_cast<GuestAddress>(contiguousBytes));
            // Check if the next page is physically contiguous in host memory
            if (nextPtr == hostPtr + contiguousBytes) {
                contiguousBytes += kPageSize;
            } else {
                break;
            }
        }

        m_impl->ScanBuffer(hostPtr, contiguousBytes, pageBase);
        pagesScanned += static_cast<uint32_t>(contiguousBytes / kPageSize);
        pageBase += contiguousBytes - kPageSize; // loop adds kPageSize
    }
}

// ============================================================================
// OnXOROperation — track runtime XOR operations for loop detection
// ============================================================================

void CryptoDetector::OnXOROperation(
    GuestAddress rip, uint8_t key,
    GuestAddress dataAddr, uint32_t size) noexcept
{
    if (!m_impl->config.enableBehaviorMonitor) return;
    m_impl->ProcessXorOperation(rip, key, dataAddr, size);
}

// ============================================================================
// OnCryptoAPICall — track WinCrypt / BCrypt API usage
// ============================================================================

void CryptoDetector::OnCryptoAPICall(
    const char* funcName, const uint64_t* args) noexcept
{
    if (!m_impl->config.enableBehaviorMonitor) return;
    m_impl->ProcessCryptoAPICall(funcName, args);
}

// ============================================================================
// GetFindings — return all detected crypto artefacts
// ============================================================================

const std::vector<CryptoFinding>&
CryptoDetector::GetFindings() const noexcept
{
    std::shared_lock lock(m_impl->mutex);
    return m_impl->findings;
}

// ============================================================================
// GetStats — compute aggregate statistics
// ============================================================================

CryptoStats CryptoDetector::GetStats() const noexcept
{
    std::shared_lock lock(m_impl->mutex);
    return m_impl->ComputeStats();
}

// ============================================================================
// GetByAlgorithm — filter findings by algorithm type
// ============================================================================

std::vector<const CryptoFinding*>
CryptoDetector::GetByAlgorithm(CryptoAlgorithm algo) const noexcept
{
    std::shared_lock lock(m_impl->mutex);

    std::vector<const CryptoFinding*> result;
    result.reserve(64);

    for (const auto& f : m_impl->findings) {
        if (f.algorithm == algo) {
            result.push_back(&f);
            if (result.size() >= kMaxFindings) break;
        }
    }

    return result;
}

// ============================================================================
// Reset — clear all state for reuse
// ============================================================================

void CryptoDetector::Reset() noexcept
{
    std::unique_lock lock(m_impl->mutex);
    m_impl->findings.clear();
    m_impl->xorRecords.clear();
    m_impl->apiCallsSeen.clear();
    m_impl->flaggedAddresses.clear();
    m_impl->hasNetworkActivity = false;
    m_impl->cryptGenRandomCount = 0;
}

} // namespace Phantom
