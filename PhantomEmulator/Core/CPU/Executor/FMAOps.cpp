/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FMAOps.cpp — Fused Multiply-Add (FMA3) instruction executor
 *
 * Implements all 30 FMA3 instructions (VEX.66.0F38 96-9F, A6-AF, B6-BF).
 * FMA is reported in CPUID leaf 1 ECX bit 12 — if we report it, we MUST
 * execute it. Failure to do so is an anti-evasion vulnerability: malware
 * that detects FMA via CPUID and then runs VFMADD will crash in the
 * emulator, revealing the sandbox.
 *
 * FMA3 encoding scheme:
 *   Opcode bits [5:4] select the operand ordering (132, 213, 231).
 *   Opcode bits [3:1] select the operation (FMADD, FMSUB, FNMADD, etc.).
 *   Opcode bit [0] selects packed (0) vs. scalar (1).
 *   VEX.W selects float (0) vs. double (1).
 *   VEX.L selects 128-bit (0) vs. 256-bit (1) for packed forms.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "AVX2Ops.hpp"
#include <cmath>
#include <cstring>

namespace Phantom {

// FMA operation type decoded from opcode bits [3:1]
enum class FMAOp : uint8_t {
    FMADDSUB = 0, // x6/x7: Alternating add/sub
    FMSUBADD = 1, // x7 variant
    FMADD    = 2, // x8/x9
    FMSUB    = 3, // xA/xB
    FNMADD   = 4, // xC/xD
    FNMSUB   = 5, // xE/xF
};

// Operand ordering decoded from opcode bits [5:4]
// 132: dest = src1 * src3 ± src2  (src1=dest, src2=vvvv, src3=rm)
// 213: dest = src2 * src1 ± src3  (src1=dest, src2=vvvv, src3=rm)
// 231: dest = src2 * src3 ± src1  (src1=dest, src2=vvvv, src3=rm)
enum class FMAOrder : uint8_t {
    Order132 = 0,  // 9x
    Order213 = 1,  // Ax
    Order231 = 2,  // Bx
};

ErrorCode CPU::ExecuteFMA(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (!inst.prefixes.hasVEX || inst.prefixes.vexPP != 1)
        return ErrorCode::UnimplementedOpcode;

    if (inst.opcodeMap != OpcodeMap::ThreeByte38)
        return ErrorCode::UnimplementedOpcode;

    const uint8_t op    = inst.opcode;
    const bool    isW1  = inst.prefixes.vexW;    // W=1: double, W=0: float
    const uint8_t vexL  = inst.prefixes.vexL;
    const bool    is256 = (vexL == 1);
    const uint32_t vecLen = is256 ? 32u : 16u;
    const uint8_t vvvv  = static_cast<uint8_t>(15 - inst.prefixes.vexVVVV);

    // Decode the operation and ordering from the opcode
    uint8_t highNibble = (op >> 4) & 0xF;
    uint8_t lowNibble  = op & 0xF;

    if (highNibble < 9 || highNibble > 0xB || lowNibble < 6)
        return ErrorCode::UnimplementedOpcode;

    FMAOrder order;
    switch (highNibble) {
        case 0x9: order = FMAOrder::Order132; break;
        case 0xA: order = FMAOrder::Order213; break;
        case 0xB: order = FMAOrder::Order231; break;
        default:  return ErrorCode::UnimplementedOpcode;
    }

    bool isScalar    = (lowNibble & 1) != 0; // Odd opcodes are scalar
    bool isMaddSub   = (lowNibble == 6 || lowNibble == 7);
    uint8_t opSelect = (lowNibble >> 1) & 0x7; // bits [3:1]

    FMAOp fmaOp;
    if (isMaddSub) {
        fmaOp = (lowNibble == 6) ? FMAOp::FMADDSUB : FMAOp::FMSUBADD;
        isScalar = false; // FMADDSUB/FMSUBADD are always packed
    } else {
        switch (opSelect) {
            case 4: fmaOp = FMAOp::FMADD;  break; // x8/x9
            case 5: fmaOp = FMAOp::FMSUB;  break; // xA/xB
            case 6: fmaOp = FMAOp::FNMADD; break; // xC/xD
            case 7: fmaOp = FMAOp::FNMSUB; break; // xE/xF
            default: return ErrorCode::UnimplementedOpcode;
        }
    }

    // Read three operand values: dest (Op0), vvvv, and r/m (Op1)
    YMMValue src1{}, src2{}, src3{};

    // src1 = destination register (will be overwritten)
    uint8_t dstIdx = inst.Op(0).reg.regIndex;
    if (is256) {
        m_state.GetYMM(dstIdx, src1.u8);
    } else {
        std::memcpy(src1.u8, m_state.XMM(dstIdx).u8, 16);
    }

    // src2 = vvvv register
    if (is256) {
        m_state.GetYMM(vvvv, src2.u8);
    } else {
        std::memcpy(src2.u8, m_state.XMM(vvvv).u8, 16);
    }

    // src3 = r/m operand
    if (inst.Op(1).IsRegister()) {
        if (is256) {
            m_state.GetYMM(inst.Op(1).reg.regIndex, src3.u8);
        } else {
            std::memcpy(src3.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
        }
    } else if (inst.Op(1).IsMemory()) {
        GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
        auto err = mem.Read(addr, src3.u8, isScalar ? (isW1 ? 8u : 4u) : vecLen);
        if (err != ErrorCode::Success) return err;
    } else {
        return ErrorCode::InvalidOperandSize;
    }

    // Assign a, b, c based on ordering:
    // The FMA operation is: result = ±(a * b) ± c
    // 132: a=src1, b=src3, c=src2
    // 213: a=src2, b=src1, c=src3
    // 231: a=src2, b=src3, c=src1
    YMMValue *a = nullptr, *b = nullptr, *c = nullptr;
    switch (order) {
        case FMAOrder::Order132: a = &src1; b = &src3; c = &src2; break;
        case FMAOrder::Order213: a = &src2; b = &src1; c = &src3; break;
        case FMAOrder::Order231: a = &src2; b = &src3; c = &src1; break;
    }

    YMMValue result{};

    if (isW1) {
        // Double-precision
        uint32_t count = isScalar ? 1u : (is256 ? 4u : 2u);
        for (uint32_t i = 0; i < count; ++i) {
            double av = a->f64[i], bv = b->f64[i], cv = c->f64[i];
            double fused = 0.0;

            switch (fmaOp) {
                case FMAOp::FMADD:    fused = std::fma(av, bv, cv);  break;
                case FMAOp::FMSUB:    fused = std::fma(av, bv, -cv); break;
                case FMAOp::FNMADD:   fused = std::fma(-av, bv, cv); break;
                case FMAOp::FNMSUB:   fused = std::fma(-av, bv, -cv); break;
                case FMAOp::FMADDSUB:
                    fused = (i & 1) ? std::fma(av, bv, cv) : std::fma(av, bv, -cv);
                    break;
                case FMAOp::FMSUBADD:
                    fused = (i & 1) ? std::fma(av, bv, -cv) : std::fma(av, bv, cv);
                    break;
            }
            result.f64[i] = fused;
        }
        // For scalar: preserve upper elements from src1 (destination)
        if (isScalar) {
            for (uint32_t i = 1; i < (is256 ? 4u : 2u); ++i)
                result.f64[i] = src1.f64[i];
        }
    } else {
        // Single-precision
        uint32_t count = isScalar ? 1u : (is256 ? 8u : 4u);
        for (uint32_t i = 0; i < count; ++i) {
            float av = a->f32[i], bv = b->f32[i], cv = c->f32[i];
            float fused = 0.0f;

            switch (fmaOp) {
                case FMAOp::FMADD:    fused = std::fmaf(av, bv, cv);  break;
                case FMAOp::FMSUB:    fused = std::fmaf(av, bv, -cv); break;
                case FMAOp::FNMADD:   fused = std::fmaf(-av, bv, cv); break;
                case FMAOp::FNMSUB:   fused = std::fmaf(-av, bv, -cv); break;
                case FMAOp::FMADDSUB:
                    fused = (i & 1) ? std::fmaf(av, bv, cv) : std::fmaf(av, bv, -cv);
                    break;
                case FMAOp::FMSUBADD:
                    fused = (i & 1) ? std::fmaf(av, bv, -cv) : std::fmaf(av, bv, cv);
                    break;
            }
            result.f32[i] = fused;
        }
        if (isScalar) {
            for (uint32_t i = 1; i < (is256 ? 8u : 4u); ++i)
                result.f32[i] = src1.f32[i];
        }
    }

    // Write result
    if (is256) {
        m_state.SetYMM(dstIdx, result.u8);
    } else {
        std::memcpy(m_state.XMM(dstIdx).u8, result.u8, 16);
        m_state.ClearYMMHigh(dstIdx);
    }

    return ErrorCode::Success;
}

} // namespace Phantom
