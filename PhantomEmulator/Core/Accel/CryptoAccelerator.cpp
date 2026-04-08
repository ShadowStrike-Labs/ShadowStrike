/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CryptoAccelerator — Hardware-accelerated crypto detection and hashing
 *
 * Uses AES-NI, SHA-NI, and PCLMULQDQ host instructions to accelerate
 * cryptographic artifact detection during emulation. Critical for ransomware
 * identification (AES key schedule detection, high-entropy region analysis)
 * and fast file hashing (SHA-256 at hardware speed).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "CryptoAccelerator.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <intrin.h>

namespace Phantom {

// ============================================================================
// Hard Caps — prevent resource exhaustion during analysis
// ============================================================================

static constexpr uint32_t kMaxKeyCandidates         = 1024;
static constexpr uint32_t kMaxSboxLocations          = 4096;
static constexpr uint32_t kMaxRoundConstLocations    = 4096;
static constexpr uint32_t kMaxEncryptedRegions       = 4096;
static constexpr uint32_t kMaxRSAKeys                = 512;
static constexpr size_t   kMaxScanSize               = 64ULL * 1024 * 1024; // 64 MB
static constexpr uint32_t kEntropyWindowSize         = 256;
static constexpr uint32_t kEntropyStride             = 128;
static constexpr double   kEncryptedThreshold        = 7.5;
static constexpr double   kCompressedThreshold       = 7.0;

// ============================================================================
// AES S-box (FIPS-197 Table)
// ============================================================================

static constexpr std::array<uint8_t, 256> kAESSbox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// AES inverse S-box
static constexpr std::array<uint8_t, 256> kAESInvSbox = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// AES round constants (RCON)
static constexpr std::array<uint8_t, 10> kAESRcon = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// SHA-256 round constants K[64] (FIPS-180-4 §4.2.2)
static constexpr std::array<uint32_t, 64> kSHA256K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// CRC32 lookup table (polynomial 0xEDB88320)
static constexpr std::array<uint32_t, 256> BuildCRC32Table() noexcept {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        table[i] = crc;
    }
    return table;
}

static constexpr std::array<uint32_t, 256> kCRC32Table = BuildCRC32Table();

// ChaCha20/Salsa20 magic constants
static constexpr uint32_t kChaCha32ByteKey_0 = 0x61707865; // "expa"
static constexpr uint32_t kChaCha32ByteKey_1 = 0x3320646E; // "nd 3"
static constexpr uint32_t kChaCha32ByteKey_2 = 0x79622D32; // "2-by"
static constexpr uint32_t kChaCha32ByteKey_3 = 0x6B206574; // "te k"

static constexpr uint32_t kChaCha16ByteKey_0 = 0x61707865; // "expa"
static constexpr uint32_t kChaCha16ByteKey_1 = 0x3120646E; // "nd 1"
static constexpr uint32_t kChaCha16ByteKey_2 = 0x79622D36; // "6-by"
static constexpr uint32_t kChaCha16ByteKey_3 = 0x6B206574; // "te k"

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct CryptoAccelerator::Impl {
    bool hasAESNI  = false;
    bool hasSHANI  = false;
    bool hasPCLMUL = false;
    bool hasSSE42  = false;

    void DetectFeatures() noexcept {
        int cpuInfo[4]{};
        __cpuid(cpuInfo, 0);
        const int maxLeaf = cpuInfo[0];

        if (maxLeaf >= 1) {
            __cpuid(cpuInfo, 1);
            hasAESNI  = ((cpuInfo[2] >> 25) & 1) != 0;
            hasPCLMUL = ((cpuInfo[2] >> 1) & 1) != 0;
            hasSSE42  = ((cpuInfo[2] >> 20) & 1) != 0;
        }

        if (maxLeaf >= 7) {
            __cpuidex(cpuInfo, 7, 0);
            hasSHANI = ((cpuInfo[1] >> 29) & 1) != 0;
        }
    }
};

// ============================================================================
// Construction / Destruction / Move
// ============================================================================

CryptoAccelerator::CryptoAccelerator() noexcept
    : m_impl(std::make_unique<Impl>())
{
    m_impl->DetectFeatures();
}

CryptoAccelerator::~CryptoAccelerator() noexcept = default;

CryptoAccelerator::CryptoAccelerator(CryptoAccelerator&&) noexcept = default;
CryptoAccelerator& CryptoAccelerator::operator=(CryptoAccelerator&&) noexcept = default;

// ============================================================================
// Feature Queries
// ============================================================================

bool CryptoAccelerator::HasAESNI() const noexcept  { return m_impl->hasAESNI; }
bool CryptoAccelerator::HasSHANI() const noexcept  { return m_impl->hasSHANI; }
bool CryptoAccelerator::HasPCLMUL() const noexcept { return m_impl->hasPCLMUL; }
bool CryptoAccelerator::HasSSE42() const noexcept  { return m_impl->hasSSE42; }

// ============================================================================
// Internal Helpers
// ============================================================================

namespace {

// Safe read of a little-endian uint32_t from a byte pointer
[[nodiscard]] inline uint32_t ReadLE32(const uint8_t* p) noexcept {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// Safe read of a big-endian uint32_t from a byte pointer
[[nodiscard]] inline uint32_t ReadBE32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

inline void WriteBE32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline void WriteBE64(uint8_t* p, uint64_t v) noexcept {
    WriteBE32(p, static_cast<uint32_t>(v >> 32));
    WriteBE32(p + 4, static_cast<uint32_t>(v));
}

// SHA-256 helper functions (FIPS-180-4 §4.1.2)
[[nodiscard]] inline uint32_t RotR(uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32 - n));
}

[[nodiscard]] inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}

[[nodiscard]] inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

[[nodiscard]] inline uint32_t Sigma0(uint32_t x) noexcept {
    return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22);
}

[[nodiscard]] inline uint32_t Sigma1(uint32_t x) noexcept {
    return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25);
}

[[nodiscard]] inline uint32_t sigma0(uint32_t x) noexcept {
    return RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3);
}

[[nodiscard]] inline uint32_t sigma1(uint32_t x) noexcept {
    return RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10);
}

// Shannon entropy of a byte buffer (0.0 – 8.0)
[[nodiscard]] double ComputeEntropy(const uint8_t* data, size_t size) noexcept {
    if (size == 0) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    const double logSize = std::log2(static_cast<double>(size));
    for (uint32_t count : freq) {
        if (count == 0) continue;
        const double p = static_cast<double>(count);
        entropy += p * (logSize - std::log2(p));
    }
    return entropy / static_cast<double>(size);
}

// Check if a 256-byte region matches the AES S-box (forward or inverse)
[[nodiscard]] bool MatchesSbox(const uint8_t* region, const std::array<uint8_t, 256>& sbox) noexcept {
    // Count matching bytes — require >=240 out of 256 (tolerance for partial tables)
    uint32_t matches = 0;
    for (uint32_t i = 0; i < 256; ++i) {
        if (region[i] == sbox[i]) {
            ++matches;
        }
    }
    return matches >= 240;
}

// Software SHA-256 block transform (FIPS-180-4 §6.2.2)
void SHA256TransformSoftware(uint32_t state[8], const uint8_t block[64]) noexcept {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = ReadBE32(block + i * 4);
    }
    for (int i = 16; i < 64; ++i) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        const uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + kSHA256K[i] + W[i];
        const uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// SHA-NI hardware SHA-256 block transform
void SHA256TransformHardware(uint32_t state[8], const uint8_t block[64]) noexcept {
    // Load current state into XMM registers
    // SHA-NI expects DCBA and HGFE order (reversed dword lanes)
    __m128i STATE0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state));
    __m128i STATE1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state + 4));

    // Save original state for addition after rounds
    const __m128i ABEF_SAVE = STATE0;
    const __m128i CDGH_SAVE = STATE1;

    // SHA-NI state layout: STATE0 = [A, B, E, F], STATE1 = [C, D, G, H]
    // Rearrange from [A, B, C, D] [E, F, G, H] to [A, B, E, F] [C, D, G, H]
    __m128i TMP = _mm_shuffle_epi32(STATE0, 0xB1);   // [B, A, D, C]
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);         // [H, G, F, E]
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);         // [A, B, E, F]
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);      // [C, D, G, H]

    // Load message block with byte-swap (big-endian)
    const __m128i MASK = _mm_set_epi64x(
        static_cast<long long>(0x0c0d0e0f08090a0bULL),
        static_cast<long long>(0x0405060700010203ULL));

    __m128i MSG0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 0)), MASK);
    __m128i MSG1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 16)), MASK);
    __m128i MSG2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 32)), MASK);
    __m128i MSG3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 48)), MASK);

    __m128i MSG;

    // Rounds 0-3
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[0])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 4-7
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[4])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 8-11
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[8])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 12-15
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[12])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 16-19
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[16])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 20-23
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[20])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 24-27
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[24])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 28-31
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[28])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 32-35
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[32])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 36-39
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[36])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 40-43
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[40])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 44-47
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[44])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 48-51
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[48])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 52-55
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[52])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 56-59
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[56])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 60-63
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&kSHA256K[60])));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Add saved state
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    // Rearrange back from [A, B, E, F] [C, D, G, H] to [A, B, C, D] [E, F, G, H]
    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);         // [F, E, B, A]
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);         // [D, C, H, G]
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);      // [A, B, C, D]
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);         // [E, F, G, H]

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state), STATE0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(state + 4), STATE1);
}

} // anonymous namespace

// ============================================================================
// SHA-256
// ============================================================================

SHA256Hash CryptoAccelerator::SHA256(ByteSpan data) const noexcept {
    SHA256Hash result{};

    // Initial hash values (FIPS-180-4 §5.3.3)
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    const size_t dataLen = data.size();
    const uint8_t* ptr = data.data();
    size_t remaining = dataLen;

    // Select transform function based on hardware support
    const bool useHW = m_impl->hasSHANI;

    // Process full 64-byte blocks
    while (remaining >= 64) {
        if (useHW) {
            SHA256TransformHardware(state, ptr);
        } else {
            SHA256TransformSoftware(state, ptr);
        }
        ptr += 64;
        remaining -= 64;
    }

    // Final block with padding (FIPS-180-4 §5.1.1)
    alignas(16) uint8_t finalBlock[128]{};
    std::memcpy(finalBlock, ptr, remaining);
    finalBlock[remaining] = 0x80;

    // Determine if we need one or two final blocks
    const size_t finalBlockCount = (remaining < 56) ? 1 : 2;
    // Length in bits goes in the last 8 bytes of the last block
    WriteBE64(finalBlock + (finalBlockCount * 64 - 8),
              static_cast<uint64_t>(dataLen) * 8);

    for (size_t i = 0; i < finalBlockCount; ++i) {
        if (useHW) {
            SHA256TransformHardware(state, finalBlock + i * 64);
        } else {
            SHA256TransformSoftware(state, finalBlock + i * 64);
        }
    }

    // Write digest in big-endian
    for (int i = 0; i < 8; ++i) {
        WriteBE32(result.bytes.data() + i * 4, state[i]);
    }

    return result;
}

// ============================================================================
// CRC32
// ============================================================================

uint32_t CryptoAccelerator::CRC32(ByteSpan data) const noexcept {
    if (data.empty()) return 0;

    const uint8_t* ptr = data.data();
    size_t len = data.size();
    uint32_t crc = 0xFFFFFFFFu;

    // SSE4.2 path: use hardware CRC32 instruction
    if (m_impl->hasSSE42) {
        // Process 8 bytes at a time using _mm_crc32_u64
        while (len >= 8) {
            uint64_t val;
            std::memcpy(&val, ptr, sizeof(val));
            crc = static_cast<uint32_t>(_mm_crc32_u64(crc, val));
            ptr += 8;
            len -= 8;
        }
        // Process remaining 4 bytes
        if (len >= 4) {
            uint32_t val;
            std::memcpy(&val, ptr, sizeof(val));
            crc = _mm_crc32_u32(crc, val);
            ptr += 4;
            len -= 4;
        }
        // Process remaining bytes
        while (len > 0) {
            crc = _mm_crc32_u8(crc, *ptr);
            ++ptr;
            --len;
        }
        return crc ^ 0xFFFFFFFFu;
    }

    // Scalar table-based fallback
    for (size_t i = 0; i < len; ++i) {
        crc = kCRC32Table[(crc ^ ptr[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

// ============================================================================
// AES Content Detection
// ============================================================================

AESDetectionResult CryptoAccelerator::DetectAESContent(
    ByteSpan data, GuestAddress baseAddr) const noexcept
{
    AESDetectionResult result{};
    if (data.empty()) return result;

    const size_t scanSize = std::min(data.size(), kMaxScanSize);
    const uint8_t* ptr = data.data();

    // --- Pass 1: Scan for AES S-box tables ---
    if (scanSize >= 256) {
        for (size_t offset = 0;
             offset <= scanSize - 256 && result.sboxLocations.size() < kMaxSboxLocations;
             ++offset)
        {
            if (MatchesSbox(ptr + offset, kAESSbox) ||
                MatchesSbox(ptr + offset, kAESInvSbox))
            {
                result.sboxLocations.push_back(baseAddr + static_cast<GuestAddress>(offset));
                result.hasAESPatterns = true;
                // Skip past this S-box to avoid duplicate detections
                offset += 255;
            }
        }
    }

    // --- Pass 2: Scan for AES round constant (RCON) sequences ---
    // Look for RCON values in proximity (within 64 bytes of each other).
    // AES key expansion uses these constants in sequence.
    if (scanSize >= 10) {
        for (size_t offset = 0;
             offset <= scanSize - 10 && result.roundConstantLocations.size() < kMaxRoundConstLocations;
             ++offset)
        {
            // Check for RCON values in a 32-bit stride pattern (as used in key schedule)
            uint32_t rconMatchCount = 0;
            size_t searchEnd = std::min(offset + 64, scanSize);
            for (size_t j = offset; j < searchEnd; ++j) {
                for (uint8_t rc : kAESRcon) {
                    if (ptr[j] == rc) {
                        ++rconMatchCount;
                        break;
                    }
                }
            }
            // If we find >=6 distinct RCON values nearby, it's likely key schedule data
            if (rconMatchCount >= 6) {
                result.roundConstantLocations.push_back(
                    baseAddr + static_cast<GuestAddress>(offset));
                result.hasAESPatterns = true;
                offset += 63;
            }
        }
    }

    // --- Pass 3: Scan for AES key candidates ---
    // Look for 16/24/32 byte aligned regions that look like AES key schedules.
    // An AES-128 expanded key is 176 bytes (11 round keys × 16 bytes).
    // AES-256 expanded key is 240 bytes (15 round keys × 16 bytes).
    static constexpr uint32_t kAES128ExpandedKeySize = 176;
    static constexpr uint32_t kAES256ExpandedKeySize = 240;

    if (scanSize >= kAES128ExpandedKeySize) {
        for (size_t offset = 0;
             offset <= scanSize - kAES128ExpandedKeySize
                 && result.keyCandidates.size() < kMaxKeyCandidates;
             offset += 4)
        {
            // Validate AES-128 key schedule: first 16 bytes are the key,
            // then each subsequent 4-byte word depends on previous words + S-box + RCON.
            const uint8_t* keyData = ptr + offset;

            // Quick entropy check — a real key schedule has moderate entropy (not all zeros or all same)
            bool allSame = true;
            bool allZero = true;
            for (uint32_t i = 0; i < 16; ++i) {
                if (keyData[i] != 0) allZero = false;
                if (keyData[i] != keyData[0]) allSame = false;
            }
            if (allZero || allSame) continue;

            // Validate AES-128 key schedule: word[i] = word[i-4] ^ SubWord(RotWord(word[i-1])) ^ RCON[i/4]
            // We check the first few round key derivations.
            bool validSchedule = true;
            uint32_t validRounds = 0;

            for (uint32_t round = 1; round <= 10 && validSchedule; ++round) {
                const uint32_t roundOffset = round * 16;
                if (offset + roundOffset + 15 >= scanSize) {
                    validSchedule = false;
                    break;
                }

                // The first word of each round key: W[4*round] = W[4*(round-1)] ^ SubWord(RotWord(W[4*round-1])) ^ RCON
                const uint8_t* prevKey = keyData + (round - 1) * 16;
                const uint8_t* curKey  = keyData + round * 16;

                // RotWord + SubWord of the last word of the previous round key
                uint8_t rotSub[4];
                rotSub[0] = kAESSbox[prevKey[13]];
                rotSub[1] = kAESSbox[prevKey[14]];
                rotSub[2] = kAESSbox[prevKey[15]];
                rotSub[3] = kAESSbox[prevKey[12]];

                uint8_t expected[4];
                expected[0] = prevKey[0] ^ rotSub[0] ^ kAESRcon[round - 1];
                expected[1] = prevKey[1] ^ rotSub[1];
                expected[2] = prevKey[2] ^ rotSub[2];
                expected[3] = prevKey[3] ^ rotSub[3];

                if (std::memcmp(curKey, expected, 4) == 0) {
                    ++validRounds;
                } else {
                    validSchedule = false;
                }
            }

            if (validRounds >= 3) {
                AESKeyCandidate candidate;
                candidate.address = baseAddr + static_cast<GuestAddress>(offset);
                candidate.keySize = 128;
                candidate.confidence = static_cast<float>(validRounds) / 10.0f;
                std::memcpy(candidate.keyBytes.data(), keyData, 16);
                result.keyCandidates.push_back(candidate);
                result.hasAESPatterns = true;
                offset += kAES128ExpandedKeySize - 4;
            }
        }
    }

    // --- Pass 4: Entropy-based encrypted region detection using AES-NI ---
    // Use AESENC on aligned 16-byte blocks. If data is already AES-encrypted,
    // applying another round won't significantly change the entropy.
    if (scanSize >= 256) {
        uint32_t highEntropyBlocks = 0;
        const uint32_t blockCount = static_cast<uint32_t>(scanSize / 256);
        for (uint32_t blk = 0; blk < blockCount; ++blk) {
            const double e = ComputeEntropy(ptr + blk * 256, 256);
            if (e > kEncryptedThreshold) {
                ++highEntropyBlocks;
            }
        }
        result.encryptedRegionCount = highEntropyBlocks;
    }

    return result;
}

// ============================================================================
// Encryption Analysis
// ============================================================================

EncryptionAnalysis CryptoAccelerator::AnalyzeEncryption(
    ByteSpan data, GuestAddress baseAddr) const noexcept
{
    EncryptionAnalysis result{};
    if (data.empty()) return result;

    const size_t scanSize = std::min(data.size(), kMaxScanSize);
    const uint8_t* ptr = data.data();

    result.totalBytes = static_cast<uint32_t>(scanSize);
    result.overallEntropy = ComputeEntropy(ptr, scanSize);

    // Sliding window entropy analysis
    EncryptedRegion currentRegion{};
    bool inRegion = false;

    for (size_t offset = 0;
         offset + kEntropyWindowSize <= scanSize
             && result.regions.size() < kMaxEncryptedRegions;
         offset += kEntropyStride)
    {
        const double windowEntropy = ComputeEntropy(ptr + offset, kEntropyWindowSize);

        if (windowEntropy > kCompressedThreshold) {
            if (!inRegion) {
                currentRegion = {};
                currentRegion.start = baseAddr + static_cast<GuestAddress>(offset);
                currentRegion.entropy = windowEntropy;
                inRegion = true;
            } else {
                // Extend current region, track max entropy
                if (windowEntropy > currentRegion.entropy) {
                    currentRegion.entropy = windowEntropy;
                }
            }

            if (windowEntropy > kEncryptedThreshold) {
                currentRegion.type = EncryptedRegion::Type::AES;
                result.encryptedBytes += kEntropyStride;
            } else {
                if (currentRegion.type == EncryptedRegion::Type::Unknown) {
                    currentRegion.type = EncryptedRegion::Type::Compressed;
                }
            }
        } else {
            if (inRegion) {
                GuestAddress regionEnd = baseAddr + static_cast<GuestAddress>(offset);
                currentRegion.size = regionEnd - currentRegion.start;
                if (currentRegion.size >= kEntropyWindowSize) {
                    result.regions.push_back(currentRegion);
                }
                inRegion = false;
            }
        }
    }

    // Close final region if still open
    if (inRegion) {
        currentRegion.size = (baseAddr + static_cast<GuestAddress>(scanSize)) - currentRegion.start;
        if (currentRegion.size >= kEntropyWindowSize) {
            result.regions.push_back(currentRegion);
        }
    }

    result.encryptedRatio = (result.totalBytes > 0)
        ? static_cast<float>(result.encryptedBytes) / static_cast<float>(result.totalBytes)
        : 0.0f;

    // Ransomware heuristic: high overall entropy + many encrypted regions + significant encrypted ratio
    result.isLikelyRansomware =
        (result.overallEntropy > kEncryptedThreshold) &&
        (result.encryptedRatio > 0.6f) &&
        (result.regions.size() >= 2);

    // Refine region types: check for ChaCha patterns within encrypted regions
    for (auto& region : result.regions) {
        if (region.type == EncryptedRegion::Type::AES && region.start >= baseAddr) {
            const size_t regionOffset = static_cast<size_t>(region.start - baseAddr);
            const size_t regionSize = static_cast<size_t>(
                std::min(region.size, static_cast<GuestSize>(scanSize - regionOffset)));
            if (regionOffset < scanSize && regionSize > 0) {
                ByteSpan regionSpan(ptr + regionOffset, regionSize);
                if (DetectChaChaPattern(regionSpan)) {
                    region.type = EncryptedRegion::Type::ChaCha;
                }
            }
        }
    }

    return result;
}

// ============================================================================
// ChaCha20/Salsa20 Detection
// ============================================================================

bool CryptoAccelerator::DetectChaChaPattern(ByteSpan data) const noexcept {
    if (data.size() < 16) return false;

    const size_t scanSize = std::min(data.size(), kMaxScanSize);
    const uint8_t* ptr = data.data();

    // Scan for "expand 32-byte k" constant (ChaCha20/Salsa20)
    for (size_t offset = 0; offset + 3 < scanSize; offset += 4) {
        const uint32_t word = ReadLE32(ptr + offset);

        // Check for the first magic constant — if found, verify the others
        if (word == kChaCha32ByteKey_0) {
            // "expand 32-byte k": constants at offsets 0, 4*4=16, 8*4=32, 12*4=48 (in state matrix)
            // But they may also appear consecutively in embedded constant tables
            // Check for adjacent constants (common in lookup tables and code)
            if (offset + 16 <= scanSize) {
                const uint32_t w1 = ReadLE32(ptr + offset + 4);
                const uint32_t w2 = ReadLE32(ptr + offset + 8);
                const uint32_t w3 = ReadLE32(ptr + offset + 12);
                if (w1 == kChaCha32ByteKey_1 && w2 == kChaCha32ByteKey_2 && w3 == kChaCha32ByteKey_3) {
                    return true;
                }
            }
            // Check for Salsa20 state layout: constants at [0], [5*4], [10*4], [15*4]
            if (offset + 60 < scanSize) {
                const uint32_t s1 = ReadLE32(ptr + offset + 20);
                const uint32_t s2 = ReadLE32(ptr + offset + 40);
                const uint32_t s3 = ReadLE32(ptr + offset + 60);
                if (s1 == kChaCha32ByteKey_1 && s2 == kChaCha32ByteKey_2 && s3 == kChaCha32ByteKey_3) {
                    return true;
                }
            }
            // ChaCha20 state layout: constants at [0], [4], [8], [12] (dword indices)
            if (offset + 48 < scanSize) {
                const uint32_t c1 = ReadLE32(ptr + offset + 16);
                const uint32_t c2 = ReadLE32(ptr + offset + 32);
                const uint32_t c3 = ReadLE32(ptr + offset + 48);
                if (c1 == kChaCha32ByteKey_1 && c2 == kChaCha32ByteKey_2 && c3 == kChaCha32ByteKey_3) {
                    return true;
                }
            }
        }

        // Check for "expand 16-byte k" (128-bit key variant)
        if (word == kChaCha16ByteKey_0 && offset + 16 <= scanSize) {
            const uint32_t w1 = ReadLE32(ptr + offset + 4);
            const uint32_t w2 = ReadLE32(ptr + offset + 8);
            const uint32_t w3 = ReadLE32(ptr + offset + 12);
            if (w1 == kChaCha16ByteKey_1 && w2 == kChaCha16ByteKey_2 && w3 == kChaCha16ByteKey_3) {
                return true;
            }
        }
    }

    // Also scan for the ASCII string directly: "expand 32-byte k" / "expand 16-byte k"
    static constexpr char kExpand32[] = "expand 32-byte k";
    static constexpr char kExpand16[] = "expand 16-byte k";
    static constexpr size_t kExpandLen = 16;

    if (scanSize >= kExpandLen) {
        for (size_t offset = 0; offset <= scanSize - kExpandLen; ++offset) {
            if (std::memcmp(ptr + offset, kExpand32, kExpandLen) == 0 ||
                std::memcmp(ptr + offset, kExpand16, kExpandLen) == 0) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// RSA Public Key Detection
// ============================================================================

std::vector<GuestAddress> CryptoAccelerator::FindRSAPublicKeys(
    ByteSpan data, GuestAddress base) const noexcept
{
    std::vector<GuestAddress> results;
    if (data.size() < 4) return results;

    const size_t scanSize = std::min(data.size(), kMaxScanSize);
    const uint8_t* ptr = data.data();

    for (size_t offset = 0;
         offset + 4 <= scanSize && results.size() < kMaxRSAKeys;
         ++offset)
    {
        // --- ASN.1 DER-encoded RSA public key ---
        // SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER, INTEGER } } }
        // Starts with: 0x30 0x82 <len_hi> <len_lo>
        // Inside, look for: 0x02 0x82 (large INTEGER — the modulus)
        if (ptr[offset] == 0x30 && ptr[offset + 1] == 0x82) {
            const uint32_t seqLen = (static_cast<uint32_t>(ptr[offset + 2]) << 8) |
                                     static_cast<uint32_t>(ptr[offset + 3]);
            // Sanity: RSA key sequence should be 128–8192 bytes
            if (seqLen >= 128 && seqLen <= 8192 && offset + 4 + seqLen <= scanSize) {
                // Scan inside for 0x02 0x82 (INTEGER with 2-byte length = large modulus)
                bool foundModulus = false;
                const size_t innerEnd = std::min(offset + 4 + seqLen, scanSize - 1);
                for (size_t inner = offset + 4; inner + 4 < innerEnd; ++inner) {
                    if (ptr[inner] == 0x02 && ptr[inner + 1] == 0x82) {
                        const uint32_t intLen = (static_cast<uint32_t>(ptr[inner + 2]) << 8) |
                                                 static_cast<uint32_t>(ptr[inner + 3]);
                        // RSA modulus: 64 bytes (512-bit) to 512 bytes (4096-bit)
                        if (intLen >= 64 && intLen <= 512) {
                            foundModulus = true;
                            break;
                        }
                    }
                }
                if (foundModulus) {
                    results.push_back(base + static_cast<GuestAddress>(offset));
                    offset += 4 + seqLen - 1;
                    continue;
                }
            }
        }

        // --- CryptoAPI PUBLICKEYSTRUC + RSAPUBKEY ---
        // PUBLICKEYSTRUC: bType=0x06(PUBLICKEYBLOB), bVersion=0x02, reserved=0x0000, aiKeyAlg
        // RSAPUBKEY:      magic='RSA1' (0x31415352), bitlen, pubexp
        if (offset + 20 <= scanSize &&
            ptr[offset] == 0x06 &&          // bType = PUBLICKEYBLOB
            ptr[offset + 1] == 0x02 &&      // bVersion = 2
            ptr[offset + 2] == 0x00 &&      // reserved
            ptr[offset + 3] == 0x00)
        {
            // Check for RSA1 magic at offset + 8
            if (offset + 12 <= scanSize) {
                const uint32_t magic = ReadLE32(ptr + offset + 8);
                if (magic == 0x31415352) {   // 'RSA1'
                    results.push_back(base + static_cast<GuestAddress>(offset));
                    // Skip past the header
                    const uint32_t bitLen = ReadLE32(ptr + offset + 12);
                    const size_t keyBytes = bitLen / 8;
                    offset += 20 + keyBytes - 1;
                    continue;
                }
            }
        }

        // Also detect RSA2 (private key blob) headers — often found alongside public keys
        if (offset + 20 <= scanSize &&
            ptr[offset] == 0x07 &&          // bType = PRIVATEKEYBLOB
            ptr[offset + 1] == 0x02 &&
            ptr[offset + 2] == 0x00 &&
            ptr[offset + 3] == 0x00)
        {
            if (offset + 12 <= scanSize) {
                const uint32_t magic = ReadLE32(ptr + offset + 8);
                if (magic == 0x32415352) {   // 'RSA2'
                    results.push_back(base + static_cast<GuestAddress>(offset));
                    offset += 19;
                    continue;
                }
            }
        }
    }

    return results;
}

} // namespace Phantom
