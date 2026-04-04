/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AESNIOps.cpp — AES-NI and PCLMULQDQ instruction emulation
 *
 * Implements Intel AES New Instructions (AES-NI) for detecting
 * malware that uses AES encryption/decryption:
 *   - AESENC / AESENCLAST    (66 0F 38 DC/DD)
 *   - AESDEC / AESDECLAST    (66 0F 38 DE/DF)
 *   - AESIMC                 (66 0F 38 DB)
 *   - AESKEYGENASSIST        (66 0F 3A DF)
 *   - PCLMULQDQ              (66 0F 3A 44)
 *
 * All AES operations follow the FIPS-197 specification exactly.
 * GF(2^8) arithmetic uses the irreducible polynomial x^8 + x^4 + x^3 + x + 1
 * (0x11B, reduction constant 0x1B).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include <cstring>

namespace Phantom {

// ============================================================================
// AES Forward S-Box (FIPS-197, Section 5.1.1)
// ============================================================================

namespace {

alignas(64) constexpr uint8_t kSBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// ============================================================================
// AES Inverse S-Box (FIPS-197, Section 5.3.2)
// ============================================================================

alignas(64) constexpr uint8_t kInvSBox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// ============================================================================
// GF(2^8) Multiplication (Russian Peasant algorithm)
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
// ============================================================================

[[nodiscard]] inline uint8_t GFMul(uint8_t a, uint8_t b) noexcept {
    uint8_t result = 0;
    uint8_t hi = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

// ============================================================================
// AES State Helpers
// The AES state is a 4x4 column-major matrix of bytes:
//   state[col][row] where state is laid out as:
//     byte[0]  = s(0,0), byte[1]  = s(1,0), byte[2]  = s(2,0), byte[3]  = s(3,0)
//     byte[4]  = s(0,1), byte[5]  = s(1,1), byte[6]  = s(2,1), byte[7]  = s(3,1)
//     byte[8]  = s(0,2), byte[9]  = s(1,2), byte[10] = s(2,2), byte[11] = s(3,2)
//     byte[12] = s(0,3), byte[13] = s(1,3), byte[14] = s(2,3), byte[15] = s(3,3)
//
// Intel defines state[i] = byte i of the XMM register (little-endian).
// Row r, Column c → index = r + 4*c
// ============================================================================

inline uint8_t StateGet(const uint8_t* s, int row, int col) noexcept {
    return s[row + 4 * col];
}

inline void StateSet(uint8_t* s, int row, int col, uint8_t val) noexcept {
    s[row + 4 * col] = val;
}

// ============================================================================
// SubBytes — apply forward S-box to every byte
// ============================================================================

inline void SubBytes(uint8_t* state) noexcept {
    for (int i = 0; i < 16; i++)
        state[i] = kSBox[state[i]];
}

// ============================================================================
// InvSubBytes — apply inverse S-box to every byte
// ============================================================================

inline void InvSubBytes(uint8_t* state) noexcept {
    for (int i = 0; i < 16; i++)
        state[i] = kInvSBox[state[i]];
}

// ============================================================================
// ShiftRows — cyclically left-shift each row by its row index
//   Row 0: no shift
//   Row 1: shift left by 1
//   Row 2: shift left by 2
//   Row 3: shift left by 3
// ============================================================================

inline void ShiftRows(uint8_t* s) noexcept {
    // Row 1: rotate left by 1
    uint8_t t = StateGet(s, 1, 0);
    StateSet(s, 1, 0, StateGet(s, 1, 1));
    StateSet(s, 1, 1, StateGet(s, 1, 2));
    StateSet(s, 1, 2, StateGet(s, 1, 3));
    StateSet(s, 1, 3, t);

    // Row 2: rotate left by 2
    uint8_t t0 = StateGet(s, 2, 0);
    uint8_t t1 = StateGet(s, 2, 1);
    StateSet(s, 2, 0, StateGet(s, 2, 2));
    StateSet(s, 2, 1, StateGet(s, 2, 3));
    StateSet(s, 2, 2, t0);
    StateSet(s, 2, 3, t1);

    // Row 3: rotate left by 3 (= right by 1)
    t = StateGet(s, 3, 3);
    StateSet(s, 3, 3, StateGet(s, 3, 2));
    StateSet(s, 3, 2, StateGet(s, 3, 1));
    StateSet(s, 3, 1, StateGet(s, 3, 0));
    StateSet(s, 3, 0, t);
}

// ============================================================================
// InvShiftRows — cyclically right-shift each row by its row index
// ============================================================================

inline void InvShiftRows(uint8_t* s) noexcept {
    // Row 1: rotate right by 1
    uint8_t t = StateGet(s, 1, 3);
    StateSet(s, 1, 3, StateGet(s, 1, 2));
    StateSet(s, 1, 2, StateGet(s, 1, 1));
    StateSet(s, 1, 1, StateGet(s, 1, 0));
    StateSet(s, 1, 0, t);

    // Row 2: rotate right by 2
    uint8_t t0 = StateGet(s, 2, 0);
    uint8_t t1 = StateGet(s, 2, 1);
    StateSet(s, 2, 0, StateGet(s, 2, 2));
    StateSet(s, 2, 1, StateGet(s, 2, 3));
    StateSet(s, 2, 2, t0);
    StateSet(s, 2, 3, t1);

    // Row 3: rotate right by 3 (= left by 1)
    t = StateGet(s, 3, 0);
    StateSet(s, 3, 0, StateGet(s, 3, 1));
    StateSet(s, 3, 1, StateGet(s, 3, 2));
    StateSet(s, 3, 2, StateGet(s, 3, 3));
    StateSet(s, 3, 3, t);
}

// ============================================================================
// MixColumns — multiply each column by the MDS matrix in GF(2^8)
//   [2 3 1 1]     [s0c]
//   [1 2 3 1]  ×  [s1c]
//   [1 1 2 3]     [s2c]
//   [3 1 1 2]     [s3c]
// ============================================================================

inline void MixColumns(uint8_t* s) noexcept {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = StateGet(s, 0, c);
        uint8_t s1 = StateGet(s, 1, c);
        uint8_t s2 = StateGet(s, 2, c);
        uint8_t s3 = StateGet(s, 3, c);

        StateSet(s, 0, c, GFMul(2, s0) ^ GFMul(3, s1) ^ s2 ^ s3);
        StateSet(s, 1, c, s0 ^ GFMul(2, s1) ^ GFMul(3, s2) ^ s3);
        StateSet(s, 2, c, s0 ^ s1 ^ GFMul(2, s2) ^ GFMul(3, s3));
        StateSet(s, 3, c, GFMul(3, s0) ^ s1 ^ s2 ^ GFMul(2, s3));
    }
}

// ============================================================================
// InvMixColumns — multiply each column by the inverse MDS matrix
//   [0E 0B 0D 09]     [s0c]
//   [09 0E 0B 0D]  ×  [s1c]
//   [0D 09 0E 0B]     [s2c]
//   [0B 0D 09 0E]     [s3c]
// ============================================================================

inline void InvMixColumns(uint8_t* s) noexcept {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = StateGet(s, 0, c);
        uint8_t s1 = StateGet(s, 1, c);
        uint8_t s2 = StateGet(s, 2, c);
        uint8_t s3 = StateGet(s, 3, c);

        StateSet(s, 0, c, GFMul(0x0E, s0) ^ GFMul(0x0B, s1) ^ GFMul(0x0D, s2) ^ GFMul(0x09, s3));
        StateSet(s, 1, c, GFMul(0x09, s0) ^ GFMul(0x0E, s1) ^ GFMul(0x0B, s2) ^ GFMul(0x0D, s3));
        StateSet(s, 2, c, GFMul(0x0D, s0) ^ GFMul(0x09, s1) ^ GFMul(0x0E, s2) ^ GFMul(0x0B, s3));
        StateSet(s, 3, c, GFMul(0x0B, s0) ^ GFMul(0x0D, s1) ^ GFMul(0x09, s2) ^ GFMul(0x0E, s3));
    }
}

// ============================================================================
// SubWord — apply S-box to each byte of a 32-bit word
// ============================================================================

[[nodiscard]] inline uint32_t SubWord(uint32_t w) noexcept {
    return (static_cast<uint32_t>(kSBox[(w >> 0)  & 0xFF])       ) |
           (static_cast<uint32_t>(kSBox[(w >> 8)  & 0xFF]) << 8  ) |
           (static_cast<uint32_t>(kSBox[(w >> 16) & 0xFF]) << 16 ) |
           (static_cast<uint32_t>(kSBox[(w >> 24) & 0xFF]) << 24 );
}

// ============================================================================
// RotWord — circular left rotation of a 32-bit word by 8 bits
// ============================================================================

[[nodiscard]] inline uint32_t RotWord(uint32_t w) noexcept {
    return (w << 8) | (w >> 24);
}

// ============================================================================
// Carry-Less Multiplication (CLMUL) of two 64-bit values
// Used by PCLMULQDQ instruction for GCM and CRC computations.
// Returns 128-bit result as two uint64_t (lo, hi).
// ============================================================================

inline void CarrylessMultiply64(uint64_t a, uint64_t b,
                                uint64_t& resultLo, uint64_t& resultHi) noexcept {
    // Use schoolbook algorithm with 64 iterations.
    // For each bit of a that is set, XOR (b << bit_position) into the result.
    resultLo = 0;
    resultHi = 0;

    for (int i = 0; i < 64; i++) {
        if ((a >> i) & 1) {
            // XOR b shifted left by i bits into the 128-bit accumulator
            if (i == 0) {
                resultLo ^= b;
            } else {
                resultLo ^= (b << i);
                resultHi ^= (b >> (64 - i));
            }
        }
    }
}

} // anonymous namespace

// ============================================================================
// AES-NI Instruction Handler
//
// Opcode map: ThreeByte38 (0F 38 xx) and ThreeByte3A (0F 3A xx)
//
// ThreeByte38 with 66 prefix:
//   0xDB — AESIMC xmm1, xmm2/m128
//   0xDC — AESENC xmm1, xmm2/m128
//   0xDD — AESENCLAST xmm1, xmm2/m128
//   0xDE — AESDEC xmm1, xmm2/m128
//   0xDF — AESDECLAST xmm1, xmm2/m128
//
// ThreeByte3A with 66 prefix:
//   0x44 — PCLMULQDQ xmm1, xmm2/m128, imm8
//   0xDF — AESKEYGENASSIST xmm1, xmm2/m128, imm8
// ============================================================================

ErrorCode CPU::ExecuteAESNI(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    bool has66 = inst.prefixes.hasOpSizeOverride;

    // All AES-NI instructions require the 66 prefix
    if (!has66) return ErrorCode::UnimplementedOpcode;

    // Helper: read 128-bit source from Op(1)
    auto ReadSrc128 = [&](uint8_t* out) -> ErrorCode {
        if (inst.Op(1).IsRegister()) {
            std::memcpy(out, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            return ErrorCode::Success;
        }
        if (inst.Op(1).IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            return mem.Read(addr, out, 16);
        }
        return ErrorCode::InvalidOperandSize;
    };

    // ====================================================================
    // ThreeByte38 (0F 38) instructions
    // ====================================================================

    if (inst.opcodeMap == OpcodeMap::ThreeByte38) {

        // ================================================================
        // AESIMC xmm1, xmm2/m128 — Inverse MixColumns transformation
        // Opcode: 66 0F 38 DB /r
        //
        // xmm1 = InvMixColumns(xmm2/m128)
        //
        // Used during equivalent-inverse cipher key expansion.
        // ================================================================
        if (op == 0xDB) {
            uint8_t src[16]{};
            auto err = ReadSrc128(src);
            if (err != ErrorCode::Success) return err;

            InvMixColumns(src);

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            std::memcpy(m_state.XMM(dstIdx).u8, src, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // AESENC xmm1, xmm2/m128 — Perform one AES encryption round
        // Opcode: 66 0F 38 DC /r
        //
        // tmp = xmm1
        // tmp = ShiftRows(tmp)
        // tmp = SubBytes(tmp)
        // tmp = MixColumns(tmp)
        // xmm1 = tmp XOR xmm2/m128 (round key)
        // ================================================================
        if (op == 0xDC) {
            uint8_t roundKey[16]{};
            auto err = ReadSrc128(roundKey);
            if (err != ErrorCode::Success) return err;

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            uint8_t state[16];
            std::memcpy(state, m_state.XMM(dstIdx).u8, 16);

            ShiftRows(state);
            SubBytes(state);
            MixColumns(state);

            for (int i = 0; i < 16; i++)
                state[i] ^= roundKey[i];

            std::memcpy(m_state.XMM(dstIdx).u8, state, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // AESENCLAST xmm1, xmm2/m128 — Final AES encryption round
        // Opcode: 66 0F 38 DD /r
        //
        // Same as AESENC but without MixColumns.
        // ================================================================
        if (op == 0xDD) {
            uint8_t roundKey[16]{};
            auto err = ReadSrc128(roundKey);
            if (err != ErrorCode::Success) return err;

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            uint8_t state[16];
            std::memcpy(state, m_state.XMM(dstIdx).u8, 16);

            ShiftRows(state);
            SubBytes(state);

            for (int i = 0; i < 16; i++)
                state[i] ^= roundKey[i];

            std::memcpy(m_state.XMM(dstIdx).u8, state, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // AESDEC xmm1, xmm2/m128 — One AES decryption round
        // Opcode: 66 0F 38 DE /r
        //
        // tmp = xmm1
        // tmp = InvShiftRows(tmp)
        // tmp = InvSubBytes(tmp)
        // tmp = InvMixColumns(tmp)
        // xmm1 = tmp XOR xmm2/m128 (round key)
        // ================================================================
        if (op == 0xDE) {
            uint8_t roundKey[16]{};
            auto err = ReadSrc128(roundKey);
            if (err != ErrorCode::Success) return err;

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            uint8_t state[16];
            std::memcpy(state, m_state.XMM(dstIdx).u8, 16);

            InvShiftRows(state);
            InvSubBytes(state);
            InvMixColumns(state);

            for (int i = 0; i < 16; i++)
                state[i] ^= roundKey[i];

            std::memcpy(m_state.XMM(dstIdx).u8, state, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // AESDECLAST xmm1, xmm2/m128 — Final AES decryption round
        // Opcode: 66 0F 38 DF /r
        //
        // Same as AESDEC but without InvMixColumns.
        // ================================================================
        if (op == 0xDF) {
            uint8_t roundKey[16]{};
            auto err = ReadSrc128(roundKey);
            if (err != ErrorCode::Success) return err;

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            uint8_t state[16];
            std::memcpy(state, m_state.XMM(dstIdx).u8, 16);

            InvShiftRows(state);
            InvSubBytes(state);

            for (int i = 0; i < 16; i++)
                state[i] ^= roundKey[i];

            std::memcpy(m_state.XMM(dstIdx).u8, state, 16);
            return ErrorCode::Success;
        }
    }

    // ====================================================================
    // ThreeByte3A (0F 3A) instructions
    // ====================================================================

    if (inst.opcodeMap == OpcodeMap::ThreeByte3A) {

        // ================================================================
        // PCLMULQDQ xmm1, xmm2/m128, imm8
        // Opcode: 66 0F 3A 44 /r ib
        //
        // Carry-less multiplication of two 64-bit quadwords.
        // imm8[0] selects source quadword from xmm1 (0=low, 1=high).
        // imm8[4] selects source quadword from xmm2 (0=low, 1=high).
        //
        // Used in AES-GCM (GHASH), CRC computation, and
        // polynomial arithmetic in GF(2^n).
        // ================================================================
        if (op == 0x44) {
            uint8_t src128[16]{};
            auto err = ReadSrc128(src128);
            if (err != ErrorCode::Success) return err;

            uint8_t imm = 0;
            if (inst.operandCount > 2 && inst.Op(2).IsImmediate()) {
                imm = static_cast<uint8_t>(inst.Op(2).imm.value);
            } else {
                return ErrorCode::InvalidOperandSize;
            }

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            XMMReg& dst = m_state.XMM(dstIdx);

            // Select 64-bit quadwords based on imm8 selector bits
            uint64_t a = (imm & 0x01) ? dst.u64[1] : dst.u64[0];
            uint64_t b;
            std::memcpy(&b, (imm & 0x10) ? &src128[8] : &src128[0], 8);

            uint64_t lo = 0, hi = 0;
            CarrylessMultiply64(a, b, lo, hi);

            dst.u64[0] = lo;
            dst.u64[1] = hi;
            return ErrorCode::Success;
        }

        // ================================================================
        // AESKEYGENASSIST xmm1, xmm2/m128, imm8
        // Opcode: 66 0F 3A DF /r ib
        //
        // Assists AES key expansion (FIPS-197 key schedule).
        //
        // Let X = xmm2/m128 interpreted as four 32-bit dwords:
        //   X3 = bits[127:96], X2 = bits[95:64],
        //   X1 = bits[63:32],  X0 = bits[31:0]
        //
        // RCON = zero-extended imm8
        //
        // xmm1[31:0]    = SubWord(X1)
        // xmm1[63:32]   = RotWord(SubWord(X1)) XOR RCON
        // xmm1[95:64]   = SubWord(X3)
        // xmm1[127:96]  = RotWord(SubWord(X3)) XOR RCON
        // ================================================================
        if (op == 0xDF) {
            uint8_t src128[16]{};
            auto err = ReadSrc128(src128);
            if (err != ErrorCode::Success) return err;

            uint8_t imm = 0;
            if (inst.operandCount > 2 && inst.Op(2).IsImmediate()) {
                imm = static_cast<uint8_t>(inst.Op(2).imm.value);
            } else {
                return ErrorCode::InvalidOperandSize;
            }

            uint32_t rcon = static_cast<uint32_t>(imm);

            // Extract 32-bit dwords from source
            uint32_t x0, x1, x2, x3;
            std::memcpy(&x0, &src128[0], 4);
            std::memcpy(&x1, &src128[4], 4);
            std::memcpy(&x2, &src128[8], 4);
            std::memcpy(&x3, &src128[12], 4);

            uint32_t sub1 = SubWord(x1);
            uint32_t sub3 = SubWord(x3);

            uint32_t d0 = sub1;
            uint32_t d1 = RotWord(sub1) ^ rcon;
            uint32_t d2 = sub3;
            uint32_t d3 = RotWord(sub3) ^ rcon;

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            XMMReg& dst = m_state.XMM(dstIdx);
            std::memcpy(&dst.u8[0],  &d0, 4);
            std::memcpy(&dst.u8[4],  &d1, 4);
            std::memcpy(&dst.u8[8],  &d2, 4);
            std::memcpy(&dst.u8[12], &d3, 4);
            return ErrorCode::Success;
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
