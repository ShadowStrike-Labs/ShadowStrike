/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SSE4Ops.cpp - SSE4.1 and SSE4.2 operations for x86/x64 emulation
 *               String comparison, CRC32, extended min/max, blend,
 *               round, insert/extract, PTEST, PCMPEQQ, PMULLD
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>

namespace Phantom {

// ============================================================================
// CRC-32C (Castagnoli) — reflected polynomial 0x82F63B78
// ============================================================================

namespace {

[[nodiscard]] bool HasOperands(const DecodedInstruction& inst, uint8_t count) noexcept {
    return inst.operandCount >= count;
}

[[nodiscard]] bool IsXmmRegisterOperand(const DecodedOperand& operand) noexcept {
    return operand.IsRegister() &&
           operand.reg.regType == RegType::XMM &&
           !operand.reg.isHighByte &&
           operand.reg.regIndex < 16;
}

[[nodiscard]] bool IsGprRegisterOperand(const DecodedOperand& operand) noexcept {
    return operand.IsRegister() &&
           operand.reg.regType == RegType::GPR &&
           operand.reg.regIndex < 16;
}

[[nodiscard]] bool IsXmmOrMemoryOperand(const DecodedOperand& operand) noexcept {
    return operand.IsMemory() || IsXmmRegisterOperand(operand);
}

[[nodiscard]] bool IsGprOrMemoryOperand(const DecodedOperand& operand) noexcept {
    return operand.IsMemory() || IsGprRegisterOperand(operand);
}

[[nodiscard]] bool HasConflictingMandatoryPrefixes(const DecodedInstruction& inst) noexcept {
    const uint8_t count = static_cast<uint8_t>(inst.prefixes.hasOpSizeOverride ? 1u : 0u) +
                          static_cast<uint8_t>(inst.prefixes.hasRep ? 1u : 0u) +
                          static_cast<uint8_t>(inst.prefixes.hasRepNE ? 1u : 0u);
    return count > 1u;
}

[[nodiscard]] uint32_t Sse4SourceReadBytes(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap == OpcodeMap::ThreeByte38) {
        switch (inst.opcode) {
            case 0x20: // PMOVSXBW
            case 0x23: // PMOVSXWD
            case 0x25: // PMOVSXDQ
            case 0x30: // PMOVZXBW
            case 0x33: // PMOVZXWD
            case 0x35: // PMOVZXDQ
                return 8;
            default:
                return 16;
        }
    }
    if (inst.opcodeMap == OpcodeMap::ThreeByte3A && (inst.opcode == 0x0A || inst.opcode == 0x21)) {
        return 4;
    }
    if (inst.opcodeMap == OpcodeMap::ThreeByte3A && inst.opcode == 0x0B) {
        return 8;
    }
    return 16;
}

[[nodiscard]] bool IsSupportedCrcSize(const DecodedInstruction& inst) noexcept {
    if (!HasOperands(inst, 2)) return false;
    if (inst.opcode == 0xF0) return inst.Op(1).size == OperandSize::Size8;
    if (inst.opcode != 0xF1) return false;
    if (inst.prefixes.rexW) return inst.Op(1).size == OperandSize::Size64;
    return inst.Op(1).size == OperandSize::Size16 || inst.Op(1).size == OperandSize::Size32;
}

[[nodiscard]] ErrorCode RequireXmmDstAndXmmOrMemSrc(const DecodedInstruction& inst) noexcept {
    if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
    return IsXmmRegisterOperand(inst.Op(0)) && IsXmmOrMemoryOperand(inst.Op(1))
        ? ErrorCode::Success
        : ErrorCode::InvalidOperandSize;
}

[[nodiscard]] ErrorCode RequireGprOrMemDstAndXmmSrc(const DecodedInstruction& inst) noexcept {
    if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
    return (IsGprRegisterOperand(inst.Op(0)) || inst.Op(0).IsMemory()) &&
           IsXmmRegisterOperand(inst.Op(1))
        ? ErrorCode::Success
        : ErrorCode::InvalidOperandSize;
}

[[nodiscard]] ErrorCode ValidateSSE4Operands(const DecodedInstruction& inst) noexcept {
    if (inst.prefixes.hasLock || inst.prefixes.hasVEX || inst.prefixes.hasEVEX ||
        HasConflictingMandatoryPrefixes(inst)) {
        return ErrorCode::UnimplementedOpcode;
    }

    const uint8_t op = inst.opcode;
    if (inst.opcodeMap == OpcodeMap::ThreeByte38 && inst.prefixes.hasOpSizeOverride) {
        if (op == 0x2A) {
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            return IsXmmRegisterOperand(inst.Op(0)) && inst.Op(1).IsMemory()
                ? ErrorCode::Success
                : ErrorCode::InvalidOperandSize;
        }
        return RequireXmmDstAndXmmOrMemSrc(inst);
    }

    if (inst.opcodeMap == OpcodeMap::ThreeByte3A && inst.prefixes.hasOpSizeOverride) {
        if (op == 0x14 || op == 0x16 || op == 0x17) {
            return RequireGprOrMemDstAndXmmSrc(inst);
        }
        if (op == 0x20 || op == 0x22) {
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            return IsXmmRegisterOperand(inst.Op(0)) && IsGprOrMemoryOperand(inst.Op(1))
                ? ErrorCode::Success
                : ErrorCode::InvalidOperandSize;
        }
        return RequireXmmDstAndXmmOrMemSrc(inst);
    }

    if (inst.opcodeMap == OpcodeMap::ThreeByte38 && inst.prefixes.hasRepNE &&
        (op == 0xF0 || op == 0xF1)) {
        if (!IsSupportedCrcSize(inst)) return ErrorCode::InvalidOperandSize;
        return IsGprRegisterOperand(inst.Op(0)) && IsGprOrMemoryOperand(inst.Op(1))
            ? ErrorCode::Success
            : ErrorCode::InvalidOperandSize;
    }

    return ErrorCode::Success;
}

[[nodiscard]] uint32_t LowDwordProduct(int32_t lhs, int32_t rhs) noexcept {
    const int64_t product = static_cast<int64_t>(lhs) * static_cast<int64_t>(rhs);
    return static_cast<uint32_t>(static_cast<uint64_t>(product));
}

[[nodiscard]] inline uint32_t CRC32C_Byte(uint32_t crc, uint8_t data) noexcept {
    crc ^= data;
    for (int i = 0; i < 8; i++) {
        if (crc & 1)
            crc = (crc >> 1) ^ 0x82F63B78u;
        else
            crc >>= 1;
    }
    return crc;
}

[[nodiscard]] inline uint32_t CRC32C_Multi(uint32_t crc, const uint8_t* data, uint32_t len) noexcept {
    for (uint32_t i = 0; i < len; i++)
        crc = CRC32C_Byte(crc, data[i]);
    return crc;
}

// ============================================================================
// SSE4.2 String Comparison Core
// ============================================================================

struct SSE42StringResult {
    uint32_t intRes2;
    bool flagCF;
    bool flagZF;
    bool flagSF;
    bool flagOF;
};

[[nodiscard]] inline SSE42StringResult SSE42_Compare(
    const XMMReg& xmm1, const XMMReg& xmm2,
    int len1, int len2, uint8_t imm8, bool isExplicit) noexcept
{
    bool isBytes = (imm8 & 1) == 0;
    bool isSigned = (imm8 & 2) != 0;
    int elemCount = isBytes ? 16 : 8;
    int agg = (imm8 >> 2) & 3;
    int polarity = (imm8 >> 4) & 3;

    if (len1 < 0) len1 = 0;
    if (len2 < 0) len2 = 0;
    if (len1 > elemCount) len1 = elemCount;
    if (len2 > elemCount) len2 = elemCount;

    auto GetElem = [&](const XMMReg& reg, int idx) -> int32_t {
        if (isBytes) {
            return isSigned ? static_cast<int32_t>(reg.i8[idx])
                            : static_cast<int32_t>(reg.u8[idx]);
        }
        return isSigned ? static_cast<int32_t>(reg.i16[idx])
                        : static_cast<int32_t>(reg.u16[idx]);
    };

    // Determine implicit lengths by finding null terminators
    int implLen1 = elemCount, implLen2 = elemCount;
    if (!isExplicit) {
        for (int i = 0; i < elemCount; i++) {
            if (GetElem(xmm1, i) == 0) { implLen1 = i; break; }
        }
        for (int i = 0; i < elemCount; i++) {
            if (GetElem(xmm2, i) == 0) { implLen2 = i; break; }
        }
        len1 = implLen1;
        len2 = implLen2;
    }

    uint32_t intRes1 = 0;

    switch (agg) {
        case 0: // Equal Any
            for (int j = 0; j < elemCount; j++) {
                if (j >= len2) break;
                for (int i = 0; i < len1; i++) {
                    if (GetElem(xmm2, j) == GetElem(xmm1, i)) {
                        intRes1 |= (1u << j);
                        break;
                    }
                }
            }
            break;
        case 1: // Ranges
            for (int j = 0; j < elemCount; j++) {
                if (j >= len2) break;
                int32_t val = GetElem(xmm2, j);
                for (int i = 0; i + 1 < len1; i += 2) {
                    int32_t lo = GetElem(xmm1, i);
                    int32_t hi = GetElem(xmm1, i + 1);
                    if (val >= lo && val <= hi) {
                        intRes1 |= (1u << j);
                        break;
                    }
                }
            }
            break;
        case 2: // Equal Each
            for (int j = 0; j < elemCount; j++) {
                if (j < len1 && j < len2) {
                    if (GetElem(xmm1, j) == GetElem(xmm2, j))
                        intRes1 |= (1u << j);
                } else if (j >= len1 && j >= len2) {
                    intRes1 |= (1u << j);
                }
            }
            break;
        case 3: { // Equal Ordered (substring)
            for (int j = 0; j < elemCount; j++) {
                if (len1 == 0 || j + len1 > len2 || j + len1 > elemCount) {
                    continue;
                }
                bool match = true;
                for (int i = 0; i < len1; i++) {
                    if (GetElem(xmm1, i) != GetElem(xmm2, j + i)) {
                        match = false;
                        break;
                    }
                }
                if (match) intRes1 |= (1u << j);
            }
            break;
        }
    }

    // Apply polarity
    uint32_t validMask = (1u << elemCount) - 1;
    uint32_t intRes2;
    switch (polarity) {
        case 0: intRes2 = intRes1; break;
        case 1: intRes2 = intRes1 ^ validMask; break;
        case 2: intRes2 = intRes1; break;
        case 3: {
            uint32_t validBits = (len2 < elemCount) ? ((1u << len2) - 1) : validMask;
            intRes2 = (intRes1 ^ validBits) & validMask;
            break;
        }
        default: intRes2 = intRes1; break;
    }
    intRes2 &= validMask;

    SSE42StringResult result{};
    result.intRes2 = intRes2;
    result.flagCF = (intRes2 != 0);
    result.flagOF = (intRes2 & 1) != 0;

    if (isExplicit) {
        result.flagZF = (len2 < elemCount);
        result.flagSF = (len1 < elemCount);
    } else {
        result.flagZF = (implLen2 < elemCount);
        result.flagSF = (implLen1 < elemCount);
    }

    return result;
}

} // anonymous namespace

// ============================================================================
// SSE4.1 / SSE4.2 Instruction Handler
// ============================================================================

ErrorCode CPU::ExecuteSSE4(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    const auto operandValidation = ValidateSSE4Operands(inst);
    if (operandValidation != ErrorCode::Success) return operandValidation;

    bool has66 = inst.prefixes.hasOpSizeOverride;
    bool hasF2 = inst.prefixes.hasRepNE;
    uint8_t op = inst.opcode;

    // Helper: read 128-bit XMM source from Op(1)
    auto ReadSrcXMM = [&](XMMReg& out) -> ErrorCode {
        if (inst.Op(1).IsRegister()) {
            out = m_state.XMM(inst.Op(1).reg.regIndex);
            return ErrorCode::Success;
        }
        if (inst.Op(1).IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            return mem.Read(addr, out.u8, Sse4SourceReadBytes(inst));
        }
        return ErrorCode::InvalidOperandSize;
    };

    // ====================================================================
    // SSE4.1 — 0F 38 xx (ThreeByte38 map, 66 prefix)
    // ====================================================================
    if (inst.opcodeMap == OpcodeMap::ThreeByte38 && has66) {

        // PTEST (66 0F 38 17)
        if (op == 0x17) {
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            const XMMReg& dst = m_state.XMM(inst.Op(0).reg.regIndex);
            uint64_t and0 = dst.u64[0] & src.u64[0];
            uint64_t and1 = dst.u64[1] & src.u64[1];
            uint64_t andn0 = (~dst.u64[0]) & src.u64[0];
            uint64_t andn1 = (~dst.u64[1]) & src.u64[1];
            m_state.eflags.Clear(Flags::CF | Flags::ZF | Flags::PF | Flags::OF | Flags::SF | Flags::AF);
            if (and0 == 0 && and1 == 0) m_state.eflags.Set(Flags::ZF);
            if (andn0 == 0 && andn1 == 0) m_state.eflags.Set(Flags::CF);
            return ErrorCode::Success;
        }

        // PCMPEQQ (66 0F 38 29)
        if (op == 0x29) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            XMMReg& dst = m_state.XMM(dstIdx);
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            dst.u64[0] = (dst.u64[0] == src.u64[0]) ? 0xFFFFFFFFFFFFFFFFULL : 0;
            dst.u64[1] = (dst.u64[1] == src.u64[1]) ? 0xFFFFFFFFFFFFFFFFULL : 0;
            return ErrorCode::Success;
        }

        // PMULDQ (66 0F 38 28) — signed dword multiply to qword
        if (op == 0x28) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            XMMReg& dst = m_state.XMM(dstIdx);
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            int64_t lo = static_cast<int64_t>(dst.i32[0]) * src.i32[0];
            int64_t hi = static_cast<int64_t>(dst.i32[2]) * src.i32[2];
            dst.i64[0] = lo;
            dst.i64[1] = hi;
            return ErrorCode::Success;
        }

        // MOVNTDQA (66 0F 38 2A) — non-temporal aligned load
        if (op == 0x2A) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                if (addr & 0xF) return ErrorCode::UnalignedAccess;
                return mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
            }
            return ErrorCode::UnimplementedOpcode;
        }

        // PMINSD (66 0F 38 38)
        if (op == 0x38) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 4; i++) d.i32[i] = std::min(d.i32[i], s.i32[i]);
            return ErrorCode::Success;
        }
        // PMINSB (66 0F 38 39)
        if (op == 0x39) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 16; i++) d.i8[i] = std::min(d.i8[i], s.i8[i]);
            return ErrorCode::Success;
        }
        // PMINUW (66 0F 38 3A)
        if (op == 0x3A) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 8; i++) d.u16[i] = std::min(d.u16[i], s.u16[i]);
            return ErrorCode::Success;
        }
        // PMINUD (66 0F 38 3B)
        if (op == 0x3B) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 4; i++) d.u32[i] = std::min(d.u32[i], s.u32[i]);
            return ErrorCode::Success;
        }
        // PMAXSD (66 0F 38 3C)
        if (op == 0x3C) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 4; i++) d.i32[i] = std::max(d.i32[i], s.i32[i]);
            return ErrorCode::Success;
        }
        // PMAXSB (66 0F 38 3D)
        if (op == 0x3D) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 16; i++) d.i8[i] = std::max(d.i8[i], s.i8[i]);
            return ErrorCode::Success;
        }
        // PMAXUW (66 0F 38 3E)
        if (op == 0x3E) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 8; i++) d.u16[i] = std::max(d.u16[i], s.u16[i]);
            return ErrorCode::Success;
        }
        // PMAXUD (66 0F 38 3F)
        if (op == 0x3F) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 4; i++) d.u32[i] = std::max(d.u32[i], s.u32[i]);
            return ErrorCode::Success;
        }

        // PMULLD (66 0F 38 40) — multiply dwords, low result
        if (op == 0x40) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 4; i++) {
                d.u32[i] = LowDwordProduct(d.i32[i], s.i32[i]);
            }
            return ErrorCode::Success;
        }

        // PHMINPOSUW (66 0F 38 41)
        if (op == 0x41) {
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            uint16_t minVal = src.u16[0];
            uint16_t minIdx = 0;
            for (int i = 1; i < 8; i++) {
                if (src.u16[i] < minVal) { minVal = src.u16[i]; minIdx = static_cast<uint16_t>(i); }
            }
            XMMReg& dst = m_state.XMM(inst.Op(0).reg.regIndex);
            dst.Clear();
            dst.u16[0] = minVal;
            dst.u16[1] = minIdx;
            return ErrorCode::Success;
        }

        // BLENDVPS (66 0F 38 14) — variable blend using XMM0
        if (op == 0x14) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            const XMMReg& mask = m_state.XMM(0);
            for (int i = 0; i < 4; i++) {
                if (mask.u32[i] & (1u << 31)) d.u32[i] = s.u32[i];
            }
            return ErrorCode::Success;
        }

        // BLENDVPD (66 0F 38 15) — variable blend doubles using XMM0
        if (op == 0x15) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            const XMMReg& mask = m_state.XMM(0);
            for (int i = 0; i < 2; i++) {
                if (mask.u64[i] & (1ULL << 63)) d.u64[i] = s.u64[i];
            }
            return ErrorCode::Success;
        }

        // PBLENDVB (66 0F 38 10) — variable blend bytes using XMM0
        if (op == 0x10) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            const XMMReg& mask = m_state.XMM(0);
            for (int i = 0; i < 16; i++) {
                if (mask.u8[i] & 0x80) d.u8[i] = s.u8[i];
            }
            return ErrorCode::Success;
        }

        // PMOVSXBW (66 0F 38 20) — sign extend 8 bytes to 8 words
        if (op == 0x20) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 7; i >= 0; i--) d.i16[i] = static_cast<int16_t>(s.i8[i]);
            return ErrorCode::Success;
        }

        // PMOVZXBW (66 0F 38 30) — zero extend 8 bytes to 8 words
        if (op == 0x30) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 7; i >= 0; i--) d.u16[i] = static_cast<uint16_t>(s.u8[i]);
            return ErrorCode::Success;
        }

        // PMOVSXWD (66 0F 38 23) — sign extend 4 words to 4 dwords
        if (op == 0x23) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 3; i >= 0; i--) d.i32[i] = static_cast<int32_t>(s.i16[i]);
            return ErrorCode::Success;
        }

        // PMOVZXWD (66 0F 38 33) — zero extend 4 words to 4 dwords
        if (op == 0x33) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 3; i >= 0; i--) d.u32[i] = static_cast<uint32_t>(s.u16[i]);
            return ErrorCode::Success;
        }

        // PMOVSXDQ (66 0F 38 25) — sign extend 2 dwords to 2 qwords
        if (op == 0x25) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            d.i64[1] = static_cast<int64_t>(s.i32[1]);
            d.i64[0] = static_cast<int64_t>(s.i32[0]);
            return ErrorCode::Success;
        }

        // PMOVZXDQ (66 0F 38 35) — zero extend 2 dwords to 2 qwords
        if (op == 0x35) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            d.u64[1] = static_cast<uint64_t>(s.u32[1]);
            d.u64[0] = static_cast<uint64_t>(s.u32[0]);
            return ErrorCode::Success;
        }
    }

    // ====================================================================
    // SSE4.1 — 0F 3A xx (ThreeByte3A map, 66 prefix)
    // ====================================================================
    if (inst.opcodeMap == OpcodeMap::ThreeByte3A && has66) {
        uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);

        // ROUNDPS (66 0F 3A 08)
        if (op == 0x08) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            uint8_t rc = imm & 3;
            for (int i = 0; i < 4; i++) {
                switch (rc) {
                    case 0: d.f32[i] = std::nearbyintf(s.f32[i]); break;
                    case 1: d.f32[i] = std::floorf(s.f32[i]); break;
                    case 2: d.f32[i] = std::ceilf(s.f32[i]); break;
                    case 3: d.f32[i] = std::truncf(s.f32[i]); break;
                }
            }
            return ErrorCode::Success;
        }
        // ROUNDPD (66 0F 3A 09)
        if (op == 0x09) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            uint8_t rc = imm & 3;
            for (int i = 0; i < 2; i++) {
                switch (rc) {
                    case 0: d.f64[i] = std::nearbyint(s.f64[i]); break;
                    case 1: d.f64[i] = std::floor(s.f64[i]); break;
                    case 2: d.f64[i] = std::ceil(s.f64[i]); break;
                    case 3: d.f64[i] = std::trunc(s.f64[i]); break;
                }
            }
            return ErrorCode::Success;
        }
        // ROUNDSS (66 0F 3A 0A)
        if (op == 0x0A) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            float v;
            if (inst.Op(1).IsRegister()) v = m_state.XMM(inst.Op(1).reg.regIndex).f32[0];
            else { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &v, 4); if (e != ErrorCode::Success) return e; }
            uint8_t rc = imm & 3;
            switch (rc) { case 0: d.f32[0] = std::nearbyintf(v); break; case 1: d.f32[0] = std::floorf(v); break; case 2: d.f32[0] = std::ceilf(v); break; case 3: d.f32[0] = std::truncf(v); break; }
            return ErrorCode::Success;
        }
        // ROUNDSD (66 0F 3A 0B)
        if (op == 0x0B) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            double v;
            if (inst.Op(1).IsRegister()) v = m_state.XMM(inst.Op(1).reg.regIndex).f64[0];
            else { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &v, 8); if (e != ErrorCode::Success) return e; }
            uint8_t rc = imm & 3;
            switch (rc) { case 0: d.f64[0] = std::nearbyint(v); break; case 1: d.f64[0] = std::floor(v); break; case 2: d.f64[0] = std::ceil(v); break; case 3: d.f64[0] = std::trunc(v); break; }
            return ErrorCode::Success;
        }

        // PBLENDW (66 0F 3A 0E imm8)
        if (op == 0x0E) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e;
            for (int i = 0; i < 8; i++) {
                if (imm & (1 << i)) d.u16[i] = s.u16[i];
            }
            return ErrorCode::Success;
        }

        // INSERTPS (66 0F 3A 21 imm8)
        if (op == 0x21) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            uint8_t countS = (imm >> 6) & 3;
            uint8_t countD = (imm >> 4) & 3;
            uint8_t zmask = imm & 0xF;
            float tmp;
            if (inst.Op(1).IsRegister()) {
                tmp = m_state.XMM(inst.Op(1).reg.regIndex).f32[countS];
            } else {
                GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst);
                auto e = mem.Read(a, &tmp, 4); if (e != ErrorCode::Success) return e;
            }
            d.f32[countD] = tmp;
            for (int i = 0; i < 4; i++) { if (zmask & (1 << i)) d.f32[i] = 0.0f; }
            return ErrorCode::Success;
        }

        // EXTRACTPS (66 0F 3A 17 imm8)
        if (op == 0x17) {
            uint8_t si = inst.Op(1).reg.regIndex;
            const XMMReg& s = m_state.XMM(si);
            uint32_t val = s.u32[imm & 3];
            return WriteOperand(inst.Op(0), inst, mem, static_cast<uint64_t>(val));
        }

        // PINSRB (66 0F 3A 20 imm8)
        if (op == 0x20) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            uint64_t v = 0; auto e = ReadOperand(inst.Op(1), inst, mem, v); if (e != ErrorCode::Success) return e;
            d.u8[imm & 0xF] = static_cast<uint8_t>(v);
            return ErrorCode::Success;
        }

        // PINSRD/PINSRQ (66 0F 3A 22 imm8)
        if (op == 0x22) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            uint64_t v = 0; auto e = ReadOperand(inst.Op(1), inst, mem, v); if (e != ErrorCode::Success) return e;
            if (inst.prefixes.rexW) d.u64[imm & 1] = v;
            else d.u32[imm & 3] = static_cast<uint32_t>(v);
            return ErrorCode::Success;
        }

        // PEXTRB (66 0F 3A 14 imm8)
        if (op == 0x14) {
            uint8_t si = inst.Op(1).reg.regIndex;
            const XMMReg& s = m_state.XMM(si);
            uint64_t val = s.u8[imm & 0xF];
            return WriteOperand(inst.Op(0), inst, mem, val);
        }

        // PEXTRD/PEXTRQ (66 0F 3A 16 imm8)
        if (op == 0x16) {
            uint8_t si = inst.Op(1).reg.regIndex;
            const XMMReg& s = m_state.XMM(si);
            uint64_t val;
            if (inst.prefixes.rexW) val = s.u64[imm & 1];
            else val = static_cast<uint64_t>(s.u32[imm & 3]);
            return WriteOperand(inst.Op(0), inst, mem, val);
        }

        // ====================================================================
        // SSE4.2 String Instructions
        // ====================================================================

        // PCMPESTRM (66 0F 3A 60 imm8) — explicit length, mask result
        if (op == 0x60) {
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            const XMMReg& xmm1 = m_state.XMM(inst.Op(0).reg.regIndex);
            int len1 = static_cast<int>(static_cast<int32_t>(m_state.GetReg32(GPR::RAX)));
            int len2 = static_cast<int>(static_cast<int32_t>(m_state.GetReg32(GPR::RDX)));
            auto result = SSE42_Compare(xmm1, src, len1, len2, imm, true);

            // Output to XMM0
            XMMReg& out = m_state.XMM(0);
            out.Clear();
            bool isBytes = (imm & 1) == 0;
            int elemCount = isBytes ? 16 : 8;
            if (imm & 0x40) {
                // Byte/word mask
                for (int i = 0; i < elemCount; i++) {
                    if (result.intRes2 & (1u << i)) {
                        if (isBytes) out.u8[i] = 0xFF; else out.u16[i] = 0xFFFF;
                    }
                }
            } else {
                // Bit mask in low bits
                out.u64[0] = result.intRes2;
            }

            m_state.eflags.Clear(Flags::CF | Flags::ZF | Flags::PF | Flags::OF | Flags::SF | Flags::AF);
            if (result.flagCF) m_state.eflags.Set(Flags::CF);
            if (result.flagZF) m_state.eflags.Set(Flags::ZF);
            if (result.flagSF) m_state.eflags.Set(Flags::SF);
            if (result.flagOF) m_state.eflags.Set(Flags::OF);
            return ErrorCode::Success;
        }

        // PCMPESTRI (66 0F 3A 61 imm8) — explicit length, index result
        if (op == 0x61) {
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            const XMMReg& xmm1 = m_state.XMM(inst.Op(0).reg.regIndex);
            int len1 = static_cast<int>(static_cast<int32_t>(m_state.GetReg32(GPR::RAX)));
            int len2 = static_cast<int>(static_cast<int32_t>(m_state.GetReg32(GPR::RDX)));
            auto result = SSE42_Compare(xmm1, src, len1, len2, imm, true);

            bool isBytes = (imm & 1) == 0;
            int elemCount = isBytes ? 16 : 8;
            uint32_t ecxVal;
            if (result.intRes2 == 0) {
                ecxVal = static_cast<uint32_t>(elemCount);
            } else if (imm & 0x40) {
                // Most significant bit
                ecxVal = 0;
                for (int i = elemCount - 1; i >= 0; i--) {
                    if (result.intRes2 & (1u << i)) { ecxVal = static_cast<uint32_t>(i); break; }
                }
            } else {
                // Least significant bit
                ecxVal = 0;
                for (int i = 0; i < elemCount; i++) {
                    if (result.intRes2 & (1u << i)) { ecxVal = static_cast<uint32_t>(i); break; }
                }
            }
            m_state.SetReg32(GPR::RCX, ecxVal);

            m_state.eflags.Clear(Flags::CF | Flags::ZF | Flags::PF | Flags::OF | Flags::SF | Flags::AF);
            if (result.flagCF) m_state.eflags.Set(Flags::CF);
            if (result.flagZF) m_state.eflags.Set(Flags::ZF);
            if (result.flagSF) m_state.eflags.Set(Flags::SF);
            if (result.flagOF) m_state.eflags.Set(Flags::OF);
            return ErrorCode::Success;
        }

        // PCMPISTRM (66 0F 3A 62 imm8) — implicit length, mask result
        if (op == 0x62) {
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            const XMMReg& xmm1 = m_state.XMM(inst.Op(0).reg.regIndex);
            auto result = SSE42_Compare(xmm1, src, 0, 0, imm, false);

            XMMReg& out = m_state.XMM(0);
            out.Clear();
            bool isBytes = (imm & 1) == 0;
            int elemCount = isBytes ? 16 : 8;
            if (imm & 0x40) {
                for (int i = 0; i < elemCount; i++) {
                    if (result.intRes2 & (1u << i)) {
                        if (isBytes) out.u8[i] = 0xFF; else out.u16[i] = 0xFFFF;
                    }
                }
            } else {
                out.u64[0] = result.intRes2;
            }

            m_state.eflags.Clear(Flags::CF | Flags::ZF | Flags::PF | Flags::OF | Flags::SF | Flags::AF);
            if (result.flagCF) m_state.eflags.Set(Flags::CF);
            if (result.flagZF) m_state.eflags.Set(Flags::ZF);
            if (result.flagSF) m_state.eflags.Set(Flags::SF);
            if (result.flagOF) m_state.eflags.Set(Flags::OF);
            return ErrorCode::Success;
        }

        // PCMPISTRI (66 0F 3A 63 imm8) — implicit length, index result
        if (op == 0x63) {
            XMMReg src{};
            auto err = ReadSrcXMM(src);
            if (err != ErrorCode::Success) return err;
            const XMMReg& xmm1 = m_state.XMM(inst.Op(0).reg.regIndex);
            auto result = SSE42_Compare(xmm1, src, 0, 0, imm, false);

            bool isBytes = (imm & 1) == 0;
            int elemCount = isBytes ? 16 : 8;
            uint32_t ecxVal;
            if (result.intRes2 == 0) {
                ecxVal = static_cast<uint32_t>(elemCount);
            } else if (imm & 0x40) {
                ecxVal = 0;
                for (int i = elemCount - 1; i >= 0; i--) {
                    if (result.intRes2 & (1u << i)) { ecxVal = static_cast<uint32_t>(i); break; }
                }
            } else {
                ecxVal = 0;
                for (int i = 0; i < elemCount; i++) {
                    if (result.intRes2 & (1u << i)) { ecxVal = static_cast<uint32_t>(i); break; }
                }
            }
            m_state.SetReg32(GPR::RCX, ecxVal);

            m_state.eflags.Clear(Flags::CF | Flags::ZF | Flags::PF | Flags::OF | Flags::SF | Flags::AF);
            if (result.flagCF) m_state.eflags.Set(Flags::CF);
            if (result.flagZF) m_state.eflags.Set(Flags::ZF);
            if (result.flagSF) m_state.eflags.Set(Flags::SF);
            if (result.flagOF) m_state.eflags.Set(Flags::OF);
            return ErrorCode::Success;
        }
    }

    // ====================================================================
    // SSE4.2 — CRC32 (F2 0F 38 F0/F1)
    // ====================================================================
    if (inst.opcodeMap == OpcodeMap::ThreeByte38 && hasF2) {
        if (op == 0xF0) {
            // CRC32 r32, r/m8
            uint32_t crc = m_state.GetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex));
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            crc = CRC32C_Byte(crc, static_cast<uint8_t>(val));
            m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), crc);
            return ErrorCode::Success;
        }
        if (op == 0xF1) {
            // CRC32 r32, r/m16/32 or CRC32 r64, r/m64
            uint32_t crc = m_state.GetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex));
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            uint32_t sz = static_cast<uint32_t>(inst.Op(1).size);
            uint8_t bytes[8];
            std::memcpy(bytes, &val, sz);
            crc = CRC32C_Multi(crc, bytes, sz);
            if (inst.prefixes.rexW) {
                m_state.SetReg64(static_cast<GPR>(inst.Op(0).reg.regIndex), crc);
            } else {
                m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), crc);
            }
            return ErrorCode::Success;
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
