/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SHAOps.cpp — SHA-NI instruction execution (Intel SHA Extensions)
 *
 * Implements the 7 SHA-NI instructions used by malware that leverages
 * hardware-accelerated SHA-1 and SHA-256 for:
 *   - Cryptographic payload verification
 *   - Custom hash-based C2 protocols
 *   - Anti-analysis (comparing SHA-256 hashes to detect debug hooks)
 *
 * Instructions:
 *   SHA1RNDS4   xmm1, xmm2/m128, imm8  (0F 3A CC)
 *   SHA1NEXTE   xmm1, xmm2/m128         (0F 38 C8)
 *   SHA1MSG1    xmm1, xmm2/m128         (0F 38 C9)
 *   SHA1MSG2    xmm1, xmm2/m128         (0F 38 CA)
 *   SHA256RNDS2 xmm1, xmm2/m128, <XMM0> (0F 38 CB)
 *   SHA256MSG1  xmm1, xmm2/m128         (0F 38 CC)
 *   SHA256MSG2  xmm1, xmm2/m128         (0F 38 CD)
 *
 * Reference: Intel SDM Vol. 2, SHA Extensions instruction set.
 * All operations work on 128-bit XMM registers only.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "../../../Common/Platform.hpp"
#include <cstring>
#include <bit>

namespace Phantom {

// ============================================================================
// SHA-1 helper functions (FIPS 180-4 §4.1.1)
// ============================================================================

namespace {

// SHA-1 non-linear function f(t, B, C, D)
[[nodiscard]] constexpr uint32_t SHA1_f(uint8_t fnIdx,
                                         uint32_t B, uint32_t C, uint32_t D) noexcept {
    switch (fnIdx) {
        case 0:  return (B & C) ^ (~B & D);            // Ch(B,C,D)
        case 1:  return B ^ C ^ D;                      // Parity(B,C,D)
        case 2:  return (B & C) ^ (B & D) ^ (C & D);   // Maj(B,C,D)
        case 3:  return B ^ C ^ D;                      // Parity(B,C,D)
        default: return 0;
    }
}

// SHA-1 constants K(t) (FIPS 180-4 §4.2.1)
[[nodiscard]] constexpr uint32_t SHA1_K(uint8_t fnIdx) noexcept {
    switch (fnIdx) {
        case 0:  return 0x5A827999u;
        case 1:  return 0x6ED9EBA1u;
        case 2:  return 0x8F1BBCDCu;
        case 3:  return 0xCA62C1D6u;
        default: return 0;
    }
}

[[nodiscard]] constexpr uint32_t RotateLeft32(uint32_t val, unsigned n) noexcept {
    const unsigned shift = n & 31u;
    return shift == 0 ? val : ((val << shift) | (val >> (32u - shift)));
}

[[nodiscard]] bool HasOperands(const DecodedInstruction& inst, uint8_t count) noexcept {
    return inst.operandCount >= count;
}

[[nodiscard]] bool IsShaOpcode(OpcodeMap map, uint8_t opcode) noexcept {
    if (map == OpcodeMap::ThreeByte38) {
        return opcode >= 0xC8 && opcode <= 0xCD;
    }
    return map == OpcodeMap::ThreeByte3A && opcode == 0xCC;
}

[[nodiscard]] bool HasInvalidShaPrefix(const DecodedInstruction& inst) noexcept {
    return inst.prefixes.hasLock ||
           inst.prefixes.hasRep ||
           inst.prefixes.hasRepNE ||
           inst.prefixes.hasOpSizeOverride ||
           inst.prefixes.hasVEX ||
           inst.prefixes.hasEVEX;
}

[[nodiscard]] bool IsXmmRegisterOperand(const DecodedOperand& operand) noexcept {
    return operand.IsRegister() &&
           operand.reg.regType == RegType::XMM &&
           !operand.reg.isHighByte &&
           operand.reg.regIndex < 16;
}

[[nodiscard]] ErrorCode ValidateShaOperands(const DecodedInstruction& inst) noexcept {
    if (!IsShaOpcode(inst.opcodeMap, inst.opcode) || HasInvalidShaPrefix(inst)) {
        return ErrorCode::UnimplementedOpcode;
    }

    const uint8_t requiredOperands = (inst.opcodeMap == OpcodeMap::ThreeByte3A) ? 3u : 2u;
    if (!HasOperands(inst, requiredOperands) || !IsXmmRegisterOperand(inst.Op(0))) {
        return ErrorCode::InvalidOperandSize;
    }

    if (!IsXmmRegisterOperand(inst.Op(1)) && !inst.Op(1).IsMemory()) {
        return ErrorCode::InvalidOperandSize;
    }

    if (inst.Op(1).IsRegister() && !IsXmmRegisterOperand(inst.Op(1))) {
        return ErrorCode::InvalidOperandSize;
    }

    if (inst.opcodeMap == OpcodeMap::ThreeByte3A && !inst.Op(2).IsImmediate()) {
        return ErrorCode::InvalidOperandSize;
    }

    return ErrorCode::Success;
}

// ============================================================================
// SHA-256 helper functions (FIPS 180-4 §4.1.2)
// ============================================================================

[[nodiscard]] constexpr uint32_t SHA256_Ch(uint32_t E, uint32_t F, uint32_t G) noexcept {
    return (E & F) ^ (~E & G);
}

[[nodiscard]] constexpr uint32_t SHA256_Maj(uint32_t A, uint32_t B, uint32_t C) noexcept {
    return (A & B) ^ (A & C) ^ (B & C);
}

[[nodiscard]] constexpr uint32_t SHA256_Sigma0(uint32_t A) noexcept {
    return RotateLeft32(A, 30) ^ RotateLeft32(A, 19) ^ RotateLeft32(A, 10);
}

[[nodiscard]] constexpr uint32_t SHA256_Sigma1(uint32_t E) noexcept {
    return RotateLeft32(E, 26) ^ RotateLeft32(E, 21) ^ RotateLeft32(E, 7);
}

[[nodiscard]] constexpr uint32_t SHA256_sigma0(uint32_t W) noexcept {
    // σ0(W) = ROTR7(W) ^ ROTR18(W) ^ SHR3(W)
    return RotateLeft32(W, 25) ^ RotateLeft32(W, 14) ^ (W >> 3);
}

[[nodiscard]] constexpr uint32_t SHA256_sigma1(uint32_t W) noexcept {
    // σ1(W) = ROTR17(W) ^ ROTR19(W) ^ SHR10(W)
    return RotateLeft32(W, 15) ^ RotateLeft32(W, 13) ^ (W >> 10);
}

} // anonymous namespace

// ============================================================================
// CPU::ExecuteSHA — SHA-NI instruction handler
// ============================================================================
// Dispatched from CPU::Dispatch for opcodes in the ThreeByte38 (C8-CD) and
// ThreeByte3A (CC) maps when no VEX prefix is present.

ErrorCode CPU::ExecuteSHA(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    const uint8_t op = inst.opcode;

    auto validation = ValidateShaOperands(inst);
    if (validation != ErrorCode::Success) return validation;

    // Read destination XMM (operand 0 — always xmm register)
    alignas(16) uint32_t dst[4]{};
    const uint8_t dstIdx = inst.Op(0).reg.regIndex;
    std::memcpy(dst, m_state.XMM(dstIdx).u8, 16);

    // Read source (operand 1 — xmm or m128)
    alignas(16) uint32_t src[4]{};
    if (inst.Op(1).IsRegister()) {
        std::memcpy(src, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
    } else if (inst.Op(1).IsMemory()) {
        GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
        auto err = mem.Read(addr, reinterpret_cast<uint8_t*>(src), 16);
        if (err != ErrorCode::Success) return err;
    } else {
        return ErrorCode::InvalidOperandSize;
    }

    // ================================================================
    // ThreeByte38 map: SHA1NEXTE (C8), SHA1MSG1 (C9), SHA1MSG2 (CA),
    //                  SHA256RNDS2 (CB), SHA256MSG1 (CC), SHA256MSG2 (CD)
    // ================================================================
    if (inst.opcodeMap == OpcodeMap::ThreeByte38) {
        switch (op) {

        // ================================================================
        // SHA1NEXTE xmm1, xmm2/m128  (NP 0F 38 C8)
        // Calculates SHA1 state variable E after 4 rounds.
        // dst[3] = ROL32(dst[3], 30) + src[3]
        // dst[0..2] = src[0..2]
        // ================================================================
        case 0xC8: {
            uint32_t result[4];
            result[3] = RotateLeft32(dst[3], 30) + src[3];
            result[2] = src[2];
            result[1] = src[1];
            result[0] = src[0];
            std::memcpy(m_state.XMM(dstIdx).u8, result, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // SHA1MSG1 xmm1, xmm2/m128  (NP 0F 38 C9)
        // Performs intermediate calculation for the next 4 SHA1 message dwords.
        // W[i] = dst[i] ^ dst[i+1]  (with wrap: dst[3] ^ src[0])
        // ================================================================
        case 0xC9: {
            uint32_t result[4];
            result[0] = dst[0] ^ dst[1];
            result[1] = dst[1] ^ dst[2];
            result[2] = dst[2] ^ dst[3];
            result[3] = dst[3] ^ src[0];
            std::memcpy(m_state.XMM(dstIdx).u8, result, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // SHA1MSG2 xmm1, xmm2/m128  (NP 0F 38 CA)
        // Performs final calculation for the next 4 SHA1 message dwords.
        // dst[i] = ROL32(dst[i] ^ src[1], 1) — with chaining
        // ================================================================
        case 0xCA: {
            uint32_t result[4];
            result[0] = RotateLeft32(dst[0] ^ src[1], 1);
            result[1] = RotateLeft32(dst[1] ^ src[2], 1);
            result[2] = RotateLeft32(dst[2] ^ src[3], 1);
            result[3] = RotateLeft32(dst[3] ^ result[0], 1);
            std::memcpy(m_state.XMM(dstIdx).u8, result, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // SHA256RNDS2 xmm1, xmm2/m128, <XMM0>  (NP 0F 38 CB)
        // Performs 2 rounds of SHA-256 operation.
        // XMM0 is an implicit operand containing the round constants + Wk.
        // State layout: xmm1 = [C, D, G, H], src = [A, B, E, F]
        // After 2 rounds: xmm1 = [A', B', E', F']
        // ================================================================
        case 0xCB: {
            // Read implicit XMM0
            alignas(16) uint32_t wk[4]{};
            std::memcpy(wk, m_state.XMM(0).u8, 16);

            // Current state from operands:
            // dst = [C, D, G, H], src = [A, B, E, F]
            uint32_t A = src[0], B = src[1], C = dst[0], D = dst[1];
            uint32_t E = src[2], F = src[3], G = dst[2], H = dst[3];

            // Round i (uses wk[0])
            {
                uint32_t T1 = H + SHA256_Sigma1(E) + SHA256_Ch(E, F, G) + wk[0];
                uint32_t T2 = SHA256_Sigma0(A) + SHA256_Maj(A, B, C);
                H = G; G = F; F = E; E = D + T1;
                D = C; C = B; B = A; A = T1 + T2;
            }

            // Round i+1 (uses wk[1])
            {
                uint32_t T1 = H + SHA256_Sigma1(E) + SHA256_Ch(E, F, G) + wk[1];
                uint32_t T2 = SHA256_Sigma0(A) + SHA256_Maj(A, B, C);
                H = G; G = F; F = E; E = D + T1;
                D = C; C = B; B = A; A = T1 + T2;
            }

            // Write back: dst = [A, B, E, F] (new state for next SHA256RNDS2)
            uint32_t result[4] = { A, B, E, F };
            std::memcpy(m_state.XMM(dstIdx).u8, result, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // SHA256MSG1 xmm1, xmm2/m128  (NP 0F 38 CC)
        // Performs intermediate calculation for the next 4 SHA-256 message dwords.
        // dst[i] = dst[i] + σ0(dst[i+1])  (with wrap: dst[3] + σ0(src[0]))
        // ================================================================
        case 0xCC: {
            uint32_t result[4];
            result[0] = dst[0] + SHA256_sigma0(dst[1]);
            result[1] = dst[1] + SHA256_sigma0(dst[2]);
            result[2] = dst[2] + SHA256_sigma0(dst[3]);
            result[3] = dst[3] + SHA256_sigma0(src[0]);
            std::memcpy(m_state.XMM(dstIdx).u8, result, 16);
            return ErrorCode::Success;
        }

        // ================================================================
        // SHA256MSG2 xmm1, xmm2/m128  (NP 0F 38 CD)
        // Performs final calculation for the next 4 SHA-256 message dwords.
        // dst[i] = dst[i] + σ1(src[j])  (with chaining)
        // ================================================================
        case 0xCD: {
            uint32_t result[4];
            result[0] = dst[0] + SHA256_sigma1(src[2]);
            result[1] = dst[1] + SHA256_sigma1(src[3]);
            result[2] = dst[2] + SHA256_sigma1(result[0]);
            result[3] = dst[3] + SHA256_sigma1(result[1]);
            std::memcpy(m_state.XMM(dstIdx).u8, result, 16);
            return ErrorCode::Success;
        }

        default:
            return ErrorCode::UnimplementedOpcode;
        }
    }

    // ================================================================
    // ThreeByte3A map: SHA1RNDS4 (CC)
    // ================================================================
    if (inst.opcodeMap == OpcodeMap::ThreeByte3A) {
        // SHA1RNDS4 xmm1, xmm2/m128, imm8  (NP 0F 3A CC)
        // Performs 4 rounds of SHA-1 operation using function selected by imm8[1:0].
        if (op == 0xCC) {
            uint8_t fnIdx = inst.Op(2).IsImmediate()
                ? static_cast<uint8_t>(inst.Op(2).imm.value & 0x03)
                : 0;

            // State: dst = [A, B, C, D], E comes from separate SHA1NEXTE
            // The instruction actually takes W[i]+K[i] in src, and A-D in dst.
            // Per Intel SDM: xmm1 holds [A,B,C,D], src holds [msg0..msg3].
            // We compute 4 rounds.
            uint32_t A = dst[0], B = dst[1], C = dst[2], D = dst[3];
            uint32_t W0 = src[0], W1 = src[1], W2 = src[2], W3 = src[3];

            // The Intel spec says src already contains W[i]+e — i.e., the
            // message schedule words are pre-added with the E state variable
            // from SHA1NEXTE. We implement 4 rounds per the SDM pseudocode.

            // Round 0
            {
                uint32_t tmp = RotateLeft32(A, 5) + SHA1_f(fnIdx, B, C, D) + W0 + SHA1_K(fnIdx);
                D = C;
                C = RotateLeft32(B, 30);
                B = A;
                A = tmp;
            }
            // Round 1
            {
                uint32_t tmp = RotateLeft32(A, 5) + SHA1_f(fnIdx, B, C, D) + W1 + SHA1_K(fnIdx);
                D = C;
                C = RotateLeft32(B, 30);
                B = A;
                A = tmp;
            }
            // Round 2
            {
                uint32_t tmp = RotateLeft32(A, 5) + SHA1_f(fnIdx, B, C, D) + W2 + SHA1_K(fnIdx);
                D = C;
                C = RotateLeft32(B, 30);
                B = A;
                A = tmp;
            }
            // Round 3
            {
                uint32_t tmp = RotateLeft32(A, 5) + SHA1_f(fnIdx, B, C, D) + W3 + SHA1_K(fnIdx);
                D = C;
                C = RotateLeft32(B, 30);
                B = A;
                A = tmp;
            }

            uint32_t result[4] = { A, B, C, D };
            std::memcpy(m_state.XMM(dstIdx).u8, result, 16);
            return ErrorCode::Success;
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
