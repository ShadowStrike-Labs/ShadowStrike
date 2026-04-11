/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AVX512Ops.cpp — AVX-512 (512-bit / EVEX-encoded) instruction executor
 *
 * Implements AVX-512F core operations with full EVEX semantics:
 *   - Opmask merge/zeroing masking (k0-k7)
 *   - 128/256/512-bit vector lengths (EVEX.LL)
 *   - Broadcast from scalar memory (EVEX.b)
 *   - ZMM0-ZMM31 register file
 *
 * Supported instruction families:
 *   - Packed integer arithmetic (VPADDB/W/D/Q, VPSUBB/W/D/Q)
 *   - Packed compare to mask (VPCMPB/W/D/Q → kmask)
 *   - Bitwise logical (VPANDD/Q, VPORD/Q, VPXORD/Q, VPANDND/Q)
 *   - Shift (VPSLLW/D/Q, VPSRLW/D/Q, VPSRAD/Q — imm and variable)
 *   - Shuffle / Permute (VPSHUFB, VPERMD/Q, VPERMB, VPTERNLOGD/Q)
 *   - Blend mask move (VMOVDQA32/64, VPBLENDMD/Q)
 *   - Broadcast (VPBROADCASTB/W/D/Q)
 *   - FP arithmetic (VADDPS/PD, VMULPS/PD, VSUBPS/PD, VDIVPS/PD)
 *   - Min/Max (VPMINSD/SQ/UD/UQ, VPMAXSD/SQ/UD/UQ)
 *   - Conversions (VCVTDQ2PS, VCVTPS2DQ, etc.)
 *   - Gather/Scatter (VPGATHERDD, VPSCATTERDD, etc.)
 *   - VNNI (VPDPBUSD, VPDPBUSDS, VPDPWSSD, VPDPWSSDS)
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "AVX2Ops.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <bit>

namespace Phantom {

// ============================================================================
// EVEX Masking — Apply opmask with merge or zeroing semantics
// ============================================================================

static void ApplyMask(
    ZMMValue& result,
    const ZMMValue& original,
    uint64_t mask,
    uint8_t elementBytes,
    bool zeroing) noexcept
{
    const uint32_t numElements = 64 / elementBytes;
    for (uint32_t i = 0; i < numElements; ++i) {
        if (!((mask >> i) & 1)) {
            if (zeroing) {
                std::memset(result.u8 + i * elementBytes, 0, elementBytes);
            } else {
                std::memcpy(result.u8 + i * elementBytes,
                            original.u8 + i * elementBytes, elementBytes);
            }
        }
    }
}

// Broadcast a scalar element across the entire ZMM register
static void Broadcast(ZMMValue& dst, const void* scalar, uint8_t elementBytes, uint32_t vecLen) noexcept {
    const uint32_t numElements = vecLen / elementBytes;
    for (uint32_t i = 0; i < numElements; ++i) {
        std::memcpy(dst.u8 + i * elementBytes, scalar, elementBytes);
    }
}

// ============================================================================
// CPU::ExecuteAVX512 — Main AVX-512 dispatch
// ============================================================================

ErrorCode CPU::ExecuteAVX512(
    const DecodedInstruction& inst,
    VirtualMemory& mem) noexcept
{
    const auto& pf = inst.prefixes;
    const uint8_t op   = inst.opcode;
    const uint8_t pp   = pf.vexPP;
    const bool    wBit = pf.vexW;

    // Vector length from EVEX.LL: 0=128(16), 1=256(32), 2=512(64)
    const uint32_t vecLen = (pf.evexLL == 2) ? 64 :
                            (pf.evexLL == 1) ? 32 : 16;

    // Opmask index and zeroing flag
    const uint8_t maskIdx = pf.evexAAA;
    const bool    zeroing = (pf.evexZ != 0);
    const bool    hasBroadcast = (pf.evexB != 0);

    // Resolve VVVV source register (inverted encoding)
    const uint8_t vvvv = static_cast<uint8_t>(
        ((pf.evexV2 ? 0 : 1) << 4) | (15 - pf.vexVVVV));

    // Element size depends on W-bit (typically: W=0 → dword, W=1 → qword)
    const uint8_t elemBytes = wBit ? 8 : 4;

    // Active mask: k0 always means "all ones" (no masking)
    uint64_t activeMask = (maskIdx == 0) ? ~0ULL
                          : m_state.opmask[maskIdx];

    // --- Helper lambdas for ZMM read/write ---
    auto ReadZMM = [&](uint8_t idx, ZMMValue& out) {
        out.Clear();
        m_state.GetZMM(idx, out.u8);
    };

    auto WriteZMM = [&](uint8_t idx, const ZMMValue& val) {
        m_state.SetZMM(idx, val.u8);
    };

    auto ReadSrc = [&](uint8_t opIdx, ZMMValue& out) -> ErrorCode {
        out.Clear();
        const auto& operand = inst.Op(opIdx);
        if (operand.IsRegister()) {
            uint8_t regIdx = operand.reg.regIndex;
            m_state.GetZMM(regIdx, out.u8);
            return ErrorCode::Success;
        }
        if (operand.IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(operand, inst);
            if (hasBroadcast) {
                // Broadcast: read scalar element, replicate
                uint8_t scalar[8]{};
                auto err = mem.Read(addr, scalar, elemBytes);
                if (err != ErrorCode::Success) return err;
                Broadcast(out, scalar, elemBytes, vecLen);
                return ErrorCode::Success;
            }
            return mem.Read(addr, out.u8, vecLen);
        }
        return ErrorCode::InvalidOperandSize;
    };

    auto WriteDst = [&](const ZMMValue& result, const ZMMValue& origDst) -> ErrorCode {
        ZMMValue final_result;
        std::memcpy(final_result.u8, result.u8, 64);
        if (maskIdx != 0) {
            ApplyMask(final_result, origDst, activeMask, elemBytes, zeroing);
        }
        const auto& dstOp = inst.Op(0);
        if (dstOp.IsRegister()) {
            WriteZMM(dstOp.reg.regIndex, final_result);
            return ErrorCode::Success;
        }
        if (dstOp.IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(dstOp, inst);
            return mem.Write(addr, final_result.u8, vecLen);
        }
        return ErrorCode::InvalidOperandSize;
    };

    // Pre-read destination for merge-masking
    ZMMValue origDst;
    origDst.Clear();
    if (inst.Op(0).IsRegister() && maskIdx != 0 && !zeroing) {
        ReadZMM(inst.Op(0).reg.regIndex, origDst);
    }

    // ========================================================================
    // Dispatch by opcode map
    // ========================================================================

    if (inst.opcodeMap == OpcodeMap::TwoByte) {
        // Map 1 (EVEX 0F)
        switch (op) {
        // ----------------------------------------------------------------
        // Packed FP arithmetic (EVEX.66.0F)
        // ----------------------------------------------------------------
        case 0x58: { // VADDPS/PD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) { // PD (double)
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.f64[i] = src1.f64[i] + src2.f64[i];
            } else { // PS (float)
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = src1.f32[i] + src2.f32[i];
            }
            return WriteDst(result, origDst);
        }
        case 0x59: { // VMULPS/PD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.f64[i] = src1.f64[i] * src2.f64[i];
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = src1.f32[i] * src2.f32[i];
            }
            return WriteDst(result, origDst);
        }
        case 0x5C: { // VSUBPS/PD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.f64[i] = src1.f64[i] - src2.f64[i];
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = src1.f32[i] - src2.f32[i];
            }
            return WriteDst(result, origDst);
        }
        case 0x5E: { // VDIVPS/PD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.f64[i] = src1.f64[i] / src2.f64[i];
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = src1.f32[i] / src2.f32[i];
            }
            return WriteDst(result, origDst);
        }
        case 0x51: { // VSQRTPS/PD
            ZMMValue src, result;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.f64[i] = std::sqrt(src.f64[i]);
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = std::sqrtf(src.f32[i]);
            }
            return WriteDst(result, origDst);
        }
        case 0x5D: { // VMINPS/PD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.f64[i] = (src2.f64[i] < src1.f64[i]) ? src2.f64[i] : src1.f64[i];
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = (src2.f32[i] < src1.f32[i]) ? src2.f32[i] : src1.f32[i];
            }
            return WriteDst(result, origDst);
        }
        case 0x5F: { // VMAXPS/PD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.f64[i] = (src2.f64[i] > src1.f64[i]) ? src2.f64[i] : src1.f64[i];
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = (src2.f32[i] > src1.f32[i]) ? src2.f32[i] : src1.f32[i];
            }
            return WriteDst(result, origDst);
        }
        case 0x54: { // VANDPS/VANDPD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                result.u64[i] = src1.u64[i] & src2.u64[i];
            return WriteDst(result, origDst);
        }
        case 0x56: { // VORPS/VORPD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                result.u64[i] = src1.u64[i] | src2.u64[i];
            return WriteDst(result, origDst);
        }
        case 0x57: { // VXORPS/VXORPD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                result.u64[i] = src1.u64[i] ^ src2.u64[i];
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // Packed integer: EVEX.66.0F
        // ----------------------------------------------------------------
        case 0x6F: { // VMOVDQA32/64 load
            ZMMValue src;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            return WriteDst(src, origDst);
        }
        case 0x7F: { // VMOVDQA32/64 store
            ZMMValue src;
            ReadZMM(inst.Op(1).reg.regIndex, src);
            // For store, destination masking applies element-wise
            if (maskIdx != 0) {
                ApplyMask(src, origDst, activeMask, elemBytes, zeroing);
            }
            const auto& dstOp = inst.Op(0);
            if (dstOp.IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(dstOp, inst);
                return mem.Write(addr, src.u8, vecLen);
            }
            if (dstOp.IsRegister()) {
                WriteZMM(dstOp.reg.regIndex, src);
                return ErrorCode::Success;
            }
            return ErrorCode::InvalidOperandSize;
        }

        case 0xFC: { // VPADDB
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen; ++i)
                result.u8[i] = src1.u8[i] + src2.u8[i];
            // Byte elements for masking
            ZMMValue origB;
            if (maskIdx != 0 && !zeroing) std::memcpy(origB.u8, origDst.u8, 64);
            else origB.Clear();
            if (maskIdx != 0) ApplyMask(result, origB, activeMask, 1, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }
        case 0xFD: { // VPADDW
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 2; ++i)
                result.u16[i] = src1.u16[i] + src2.u16[i];
            ZMMValue origW;
            if (maskIdx != 0 && !zeroing) std::memcpy(origW.u8, origDst.u8, 64);
            else origW.Clear();
            if (maskIdx != 0) ApplyMask(result, origW, activeMask, 2, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }
        case 0xFE: { // VPADDD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                result.u32[i] = src1.u32[i] + src2.u32[i];
            return WriteDst(result, origDst);
        }
        case 0xD4: { // VPADDQ
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                result.u64[i] = src1.u64[i] + src2.u64[i];
            return WriteDst(result, origDst);
        }
        case 0xF8: { // VPSUBB
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen; ++i)
                result.u8[i] = src1.u8[i] - src2.u8[i];
            ZMMValue origB;
            if (maskIdx != 0 && !zeroing) std::memcpy(origB.u8, origDst.u8, 64);
            else origB.Clear();
            if (maskIdx != 0) ApplyMask(result, origB, activeMask, 1, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }
        case 0xF9: { // VPSUBW
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 2; ++i)
                result.u16[i] = src1.u16[i] - src2.u16[i];
            ZMMValue origW;
            if (maskIdx != 0 && !zeroing) std::memcpy(origW.u8, origDst.u8, 64);
            else origW.Clear();
            if (maskIdx != 0) ApplyMask(result, origW, activeMask, 2, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }
        case 0xFA: { // VPSUBD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                result.u32[i] = src1.u32[i] - src2.u32[i];
            return WriteDst(result, origDst);
        }
        case 0xFB: { // VPSUBQ
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                result.u64[i] = src1.u64[i] - src2.u64[i];
            return WriteDst(result, origDst);
        }

        // Packed compare equal (result to register, not kmask, in some forms)
        case 0x76: { // VPCMPEQD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                result.u32[i] = (src1.u32[i] == src2.u32[i]) ? 0xFFFFFFFFu : 0;
            return WriteDst(result, origDst);
        }

        // Shifts
        case 0x72: { // VPSRLD/VPSLLD/VPSRAD imm (ext=2/6/4)
            ZMMValue src, result;
            ReadZMM(vvvv, src);
            uint8_t count = static_cast<uint8_t>(inst.Op(1).imm.value);
            uint8_t ext = inst.opcodeExt;
            // Read from inst operand that has the register
            result.Clear();
            if (ext == 2) { // VPSRLD
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.u32[i] = (count >= 32) ? 0 : (src.u32[i] >> count);
            } else if (ext == 6) { // VPSLLD
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.u32[i] = (count >= 32) ? 0 : (src.u32[i] << count);
            } else if (ext == 4) { // VPSRAD
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.i32[i] = (count >= 32)
                        ? (src.i32[i] >> 31) : (src.i32[i] >> count);
            }
            return WriteDst(result, origDst);
        }
        case 0x73: { // VPSRLQ/VPSLLQ imm (ext=2/6)
            ZMMValue src, result;
            ReadZMM(vvvv, src);
            uint8_t count = static_cast<uint8_t>(inst.Op(1).imm.value);
            uint8_t ext = inst.opcodeExt;
            result.Clear();
            if (ext == 2) { // VPSRLQ
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.u64[i] = (count >= 64) ? 0 : (src.u64[i] >> count);
            } else if (ext == 6) { // VPSLLQ
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.u64[i] = (count >= 64) ? 0 : (src.u64[i] << count);
            }
            return WriteDst(result, origDst);
        }

        // Shuffle
        case 0xC6: { // VSHUFPS/VSHUFPD
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.Op(2).imm.value);
            result.Clear();
            if (!wBit) { // PS — dword shuffle within 128-bit lanes
                for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                    auto* r = reinterpret_cast<uint32_t*>(result.u8 + lane);
                    auto* s1 = reinterpret_cast<const uint32_t*>(src1.u8 + lane);
                    auto* s2 = reinterpret_cast<const uint32_t*>(src2.u8 + lane);
                    r[0] = s1[(imm >> 0) & 3];
                    r[1] = s1[(imm >> 2) & 3];
                    r[2] = s2[(imm >> 4) & 3];
                    r[3] = s2[(imm >> 6) & 3];
                }
            } else { // PD — qword shuffle within 128-bit lanes
                for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                    auto* r = reinterpret_cast<uint64_t*>(result.u8 + lane);
                    auto* s1 = reinterpret_cast<const uint64_t*>(src1.u8 + lane);
                    auto* s2 = reinterpret_cast<const uint64_t*>(src2.u8 + lane);
                    uint32_t laneIdx = lane / 16;
                    r[0] = s1[(imm >> (laneIdx * 2)) & 1];
                    r[1] = s2[(imm >> (laneIdx * 2 + 1)) & 1];
                }
            }
            return WriteDst(result, origDst);
        }

        // Unpack
        case 0x60: { // VPUNPCKLBW
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                for (uint32_t i = 0; i < 8; ++i) {
                    result.u8[lane + i * 2]     = src1.u8[lane + i];
                    result.u8[lane + i * 2 + 1] = src2.u8[lane + i];
                }
            }
            ZMMValue origB;
            if (maskIdx != 0 && !zeroing) std::memcpy(origB.u8, origDst.u8, 64);
            else origB.Clear();
            if (maskIdx != 0) ApplyMask(result, origB, activeMask, 1, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }

        // Conversions
        case 0x5B: { // VCVTDQ2PS (W=0) / VCVTPS2DQ (pp=66 W=0)
            ZMMValue src, result;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (pp == 0) { // VCVTDQ2PS
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.f32[i] = static_cast<float>(src.i32[i]);
            } else { // pp=1 → VCVTPS2DQ
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    float v = src.f32[i];
                    if (v >= 2147483648.0f) result.i32[i] = 0x7FFFFFFF;
                    else if (v < -2147483648.0f) result.i32[i] = static_cast<int32_t>(0x80000000u);
                    else result.i32[i] = static_cast<int32_t>(std::nearbyintf(v));
                }
            }
            return WriteDst(result, origDst);
        }

        // VPANDD/Q, VPORD/Q, VPXORD/Q (EVEX.0F)
        case 0xDB: { // VPANDD/Q
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < 8; ++i)
                result.u64[i] = src1.u64[i] & src2.u64[i];
            return WriteDst(result, origDst);
        }
        case 0xEB: { // VPORD/Q
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < 8; ++i)
                result.u64[i] = src1.u64[i] | src2.u64[i];
            return WriteDst(result, origDst);
        }
        case 0xEF: { // VPXORD/Q
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < 8; ++i)
                result.u64[i] = src1.u64[i] ^ src2.u64[i];
            return WriteDst(result, origDst);
        }
        case 0xDF: { // VPANDND/Q
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < 8; ++i)
                result.u64[i] = (~src1.u64[i]) & src2.u64[i];
            return WriteDst(result, origDst);
        }

        // Broadcast
        case 0x78: { // VPBROADCASTB (EVEX.66.0F38 in some, but aliased here)
            // Fallthrough if not handled
            break;
        }

        default:
            break;
        }
    }
    else if (inst.opcodeMap == OpcodeMap::ThreeByte38) {
        // Map 2 (EVEX 0F 38)
        switch (op) {

        // ----------------------------------------------------------------
        // VPBROADCAST family
        // ----------------------------------------------------------------
        case 0x78: { // VPBROADCASTB
            ZMMValue result;
            result.Clear();
            uint8_t val = 0;
            if (inst.Op(1).IsRegister()) {
                val = static_cast<uint8_t>(m_state.GetRegBySize(
                    static_cast<GPR>(inst.Op(1).reg.regIndex), OperandSize::Size8));
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, &val, 1);
                if (err != ErrorCode::Success) return err;
            }
            for (uint32_t i = 0; i < vecLen; ++i) result.u8[i] = val;
            ZMMValue origB;
            if (maskIdx != 0 && !zeroing) std::memcpy(origB.u8, origDst.u8, 64);
            else origB.Clear();
            if (maskIdx != 0) ApplyMask(result, origB, activeMask, 1, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }
        case 0x79: { // VPBROADCASTW
            ZMMValue result;
            result.Clear();
            uint16_t val = 0;
            if (inst.Op(1).IsRegister()) {
                val = static_cast<uint16_t>(m_state.GetRegBySize(
                    static_cast<GPR>(inst.Op(1).reg.regIndex), OperandSize::Size16));
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, &val, 2);
                if (err != ErrorCode::Success) return err;
            }
            for (uint32_t i = 0; i < vecLen / 2; ++i) result.u16[i] = val;
            ZMMValue origW;
            if (maskIdx != 0 && !zeroing) std::memcpy(origW.u8, origDst.u8, 64);
            else origW.Clear();
            if (maskIdx != 0) ApplyMask(result, origW, activeMask, 2, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }
        case 0x58: { // VPBROADCASTD
            ZMMValue result;
            result.Clear();
            uint32_t val = 0;
            if (inst.Op(1).IsRegister()) {
                if (inst.Op(1).reg.regType == RegType::XMM || inst.Op(1).reg.regType == RegType::ZMM) {
                    XMMReg tmp;
                    tmp = m_state.XMM(inst.Op(1).reg.regIndex);
                    val = tmp.u32[0];
                } else {
                    val = m_state.GetReg32(static_cast<GPR>(inst.Op(1).reg.regIndex));
                }
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, &val, 4);
                if (err != ErrorCode::Success) return err;
            }
            for (uint32_t i = 0; i < vecLen / 4; ++i) result.u32[i] = val;
            return WriteDst(result, origDst);
        }
        case 0x59: { // VPBROADCASTQ
            ZMMValue result;
            result.Clear();
            uint64_t val = 0;
            if (inst.Op(1).IsRegister()) {
                if (inst.Op(1).reg.regType == RegType::XMM || inst.Op(1).reg.regType == RegType::ZMM) {
                    XMMReg tmp;
                    tmp = m_state.XMM(inst.Op(1).reg.regIndex);
                    val = tmp.u64[0];
                } else {
                    val = m_state.GetReg64(static_cast<GPR>(inst.Op(1).reg.regIndex));
                }
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, &val, 8);
                if (err != ErrorCode::Success) return err;
            }
            for (uint32_t i = 0; i < vecLen / 8; ++i) result.u64[i] = val;
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // Packed min/max (signed/unsigned dword/qword)
        // ----------------------------------------------------------------
        case 0x39: { // VPMINSD (W=0) / VPMINSQ (W=1)
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.i64[i] = std::min(src1.i64[i], src2.i64[i]);
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.i32[i] = std::min(src1.i32[i], src2.i32[i]);
            }
            return WriteDst(result, origDst);
        }
        case 0x3B: { // VPMINUD (W=0) / VPMINUQ (W=1)
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.u64[i] = std::min(src1.u64[i], src2.u64[i]);
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.u32[i] = std::min(src1.u32[i], src2.u32[i]);
            }
            return WriteDst(result, origDst);
        }
        case 0x3D: { // VPMAXSD (W=0) / VPMAXSQ (W=1)
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.i64[i] = std::max(src1.i64[i], src2.i64[i]);
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.i32[i] = std::max(src1.i32[i], src2.i32[i]);
            }
            return WriteDst(result, origDst);
        }
        case 0x3F: { // VPMAXUD (W=0) / VPMAXUQ (W=1)
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.u64[i] = std::max(src1.u64[i], src2.u64[i]);
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.u32[i] = std::max(src1.u32[i], src2.u32[i]);
            }
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // VPTERNLOGD/Q (0F38 25) — Ternary logic on 3 sources
        // ----------------------------------------------------------------
        case 0x25: {
            ZMMValue src1, src2, src3, result;
            ReadZMM(inst.Op(0).reg.regIndex, src1); // dst is also src1
            ReadZMM(vvvv, src2);
            auto err = ReadSrc(2, src3);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.Op(3).imm.value);
            result.Clear();
            if (wBit) { // VPTERNLOGQ
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    uint64_t a = src1.u64[i], b = src2.u64[i], c = src3.u64[i];
                    uint64_t r = 0;
                    for (int bit = 0; bit < 64; ++bit) {
                        uint8_t idx = static_cast<uint8_t>(
                            (((a >> bit) & 1) << 2) |
                            (((b >> bit) & 1) << 1) |
                            ((c >> bit) & 1));
                        r |= static_cast<uint64_t>((imm >> idx) & 1) << bit;
                    }
                    result.u64[i] = r;
                }
            } else { // VPTERNLOGD
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    uint32_t a = src1.u32[i], b = src2.u32[i], c = src3.u32[i];
                    uint32_t r = 0;
                    for (int bit = 0; bit < 32; ++bit) {
                        uint8_t idx = static_cast<uint8_t>(
                            (((a >> bit) & 1) << 2) |
                            (((b >> bit) & 1) << 1) |
                            ((c >> bit) & 1));
                        r |= static_cast<uint32_t>((imm >> idx) & 1) << bit;
                    }
                    result.u32[i] = r;
                }
            }
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // VPERMD/Q (0F38 36/16)
        // ----------------------------------------------------------------
        case 0x36: { // VPERMD (W=0) / VPERMQ (W=1)
            ZMMValue idx_vec, src, result;
            ReadZMM(vvvv, idx_vec);
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                uint32_t count = vecLen / 8;
                for (uint32_t i = 0; i < count; ++i) {
                    uint64_t sel = idx_vec.u64[i] & (count - 1);
                    result.u64[i] = src.u64[sel];
                }
            } else {
                uint32_t count = vecLen / 4;
                for (uint32_t i = 0; i < count; ++i) {
                    uint32_t sel = idx_vec.u32[i] & (count - 1);
                    result.u32[i] = src.u32[sel];
                }
            }
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // VPSHUFB (0F38 00) — Byte-level shuffle
        // ----------------------------------------------------------------
        case 0x00: {
            ZMMValue src, ctrl, result;
            ReadZMM(vvvv, src);
            auto err = ReadSrc(1, ctrl);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            // VPSHUFB operates within 128-bit lanes
            for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                for (uint32_t i = 0; i < 16; ++i) {
                    uint8_t c = ctrl.u8[lane + i];
                    if (c & 0x80) {
                        result.u8[lane + i] = 0;
                    } else {
                        result.u8[lane + i] = src.u8[lane + (c & 0x0F)];
                    }
                }
            }
            ZMMValue origB;
            if (maskIdx != 0 && !zeroing) std::memcpy(origB.u8, origDst.u8, 64);
            else origB.Clear();
            if (maskIdx != 0) ApplyMask(result, origB, activeMask, 1, zeroing);
            const auto& d = inst.Op(0);
            if (d.IsRegister()) { WriteZMM(d.reg.regIndex, result); return ErrorCode::Success; }
            return ErrorCode::InvalidOperandSize;
        }

        // ----------------------------------------------------------------
        // VPMULLD (0F38 40 W=0) / VPMULLQ (0F38 40 W=1)
        // ----------------------------------------------------------------
        case 0x40: {
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) { // VPMULLQ
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    result.u64[i] = src1.u64[i] * src2.u64[i]; // Low 64 bits
            } else { // VPMULLD
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    result.u32[i] = src1.u32[i] * src2.u32[i]; // Low 32 bits
            }
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // VNNI: VPDPBUSD/VPDPBUSDS/VPDPWSSD/VPDPWSSDS (0F38 50-53)
        // ----------------------------------------------------------------
        case 0x50: { // VPDPBUSD
            ZMMValue acc, src1, src2;
            ReadZMM(inst.Op(0).reg.regIndex, acc);
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(2, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                int32_t sum = acc.i32[i];
                for (int j = 0; j < 4; ++j) {
                    uint8_t a = src1.u8[i * 4 + j];    // unsigned
                    int8_t  b = src2.i8[i * 4 + j];    // signed
                    sum += static_cast<int32_t>(a) * static_cast<int32_t>(b);
                }
                acc.i32[i] = sum;
            }
            return WriteDst(acc, origDst);
        }
        case 0x51: { // VPDPBUSDS (saturating)
            ZMMValue acc, src1, src2;
            ReadZMM(inst.Op(0).reg.regIndex, acc);
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(2, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                int64_t sum = static_cast<int64_t>(acc.i32[i]);
                for (int j = 0; j < 4; ++j) {
                    uint8_t a = src1.u8[i * 4 + j];
                    int8_t  b = src2.i8[i * 4 + j];
                    sum += static_cast<int64_t>(a) * static_cast<int64_t>(b);
                }
                if (sum > INT32_MAX) sum = INT32_MAX;
                if (sum < INT32_MIN) sum = INT32_MIN;
                acc.i32[i] = static_cast<int32_t>(sum);
            }
            return WriteDst(acc, origDst);
        }
        case 0x52: { // VPDPWSSD
            ZMMValue acc, src1, src2;
            ReadZMM(inst.Op(0).reg.regIndex, acc);
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(2, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                int32_t sum = acc.i32[i];
                for (int j = 0; j < 2; ++j) {
                    int16_t a = src1.i16[i * 2 + j];
                    int16_t b = src2.i16[i * 2 + j];
                    sum += static_cast<int32_t>(a) * static_cast<int32_t>(b);
                }
                acc.i32[i] = sum;
            }
            return WriteDst(acc, origDst);
        }
        case 0x53: { // VPDPWSSDS (saturating)
            ZMMValue acc, src1, src2;
            ReadZMM(inst.Op(0).reg.regIndex, acc);
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(2, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                int64_t sum = static_cast<int64_t>(acc.i32[i]);
                for (int j = 0; j < 2; ++j) {
                    int16_t a = src1.i16[i * 2 + j];
                    int16_t b = src2.i16[i * 2 + j];
                    sum += static_cast<int64_t>(a) * static_cast<int64_t>(b);
                }
                if (sum > INT32_MAX) sum = INT32_MAX;
                if (sum < INT32_MIN) sum = INT32_MIN;
                acc.i32[i] = static_cast<int32_t>(sum);
            }
            return WriteDst(acc, origDst);
        }

        // ----------------------------------------------------------------
        // Opmask operations: VPCMPD/Q → k (0F38 1F for VPCMPD)
        // These set a kmask register instead of a vector register
        // ----------------------------------------------------------------

        // ----------------------------------------------------------------
        // AES-NI under EVEX (VAES): DC-DF
        // ----------------------------------------------------------------
        case 0xDC: { // VAESENC
            ZMMValue state, key, result;
            ReadZMM(vvvv, state);
            auto err = ReadSrc(1, key);
            if (err != ErrorCode::Success) return err;
            // AES operates in 128-bit blocks
            // Process each 128-bit lane independently
            result.Clear();
            for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                // Delegate to the AES round function
                // For simplicity, call the existing SSE AES handler per lane
                // by constructing the lane data and processing
                uint8_t stateBlock[16], keyBlock[16], outBlock[16];
                std::memcpy(stateBlock, state.u8 + lane, 16);
                std::memcpy(keyBlock, key.u8 + lane, 16);

                // AES ShiftRows + SubBytes + MixColumns + AddRoundKey
                // Inline the AES round for correctness (FIPS 197)
                // SubBytes
                static constexpr uint8_t sbox[256] = {
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

                // ShiftRows
                uint8_t sr[16];
                sr[0]  = sbox[stateBlock[0]];  sr[1]  = sbox[stateBlock[5]];
                sr[2]  = sbox[stateBlock[10]]; sr[3]  = sbox[stateBlock[15]];
                sr[4]  = sbox[stateBlock[4]];  sr[5]  = sbox[stateBlock[9]];
                sr[6]  = sbox[stateBlock[14]]; sr[7]  = sbox[stateBlock[3]];
                sr[8]  = sbox[stateBlock[8]];  sr[9]  = sbox[stateBlock[13]];
                sr[10] = sbox[stateBlock[2]];  sr[11] = sbox[stateBlock[7]];
                sr[12] = sbox[stateBlock[12]]; sr[13] = sbox[stateBlock[1]];
                sr[14] = sbox[stateBlock[6]];  sr[15] = sbox[stateBlock[11]];

                // MixColumns (GF(2^8) multiply)
                auto xtime = [](uint8_t x) -> uint8_t {
                    return static_cast<uint8_t>((x << 1) ^ ((x >> 7) * 0x1B));
                };
                for (int col = 0; col < 4; ++col) {
                    uint8_t a0 = sr[col * 4], a1 = sr[col * 4 + 1];
                    uint8_t a2 = sr[col * 4 + 2], a3 = sr[col * 4 + 3];
                    outBlock[col * 4]     = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
                    outBlock[col * 4 + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
                    outBlock[col * 4 + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
                    outBlock[col * 4 + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
                }

                // AddRoundKey (XOR with key)
                for (int i = 0; i < 16; ++i)
                    outBlock[i] ^= keyBlock[i];

                std::memcpy(result.u8 + lane, outBlock, 16);
            }
            return WriteDst(result, origDst);
        }
        case 0xDD: { // VAESDEC — similar structure to VAESENC but inverse
            ZMMValue state, key, result;
            ReadZMM(vvvv, state);
            auto err = ReadSrc(1, key);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                uint8_t stateBlock[16], keyBlock[16], outBlock[16];
                std::memcpy(stateBlock, state.u8 + lane, 16);
                std::memcpy(keyBlock, key.u8 + lane, 16);

                // Inverse AES round: InvShiftRows + InvSubBytes + InvMixColumns + AddRoundKey
                static constexpr uint8_t inv_sbox[256] = {
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

                // InvShiftRows + InvSubBytes
                uint8_t isr[16];
                isr[0]  = inv_sbox[stateBlock[0]];  isr[5]  = inv_sbox[stateBlock[1]];
                isr[10] = inv_sbox[stateBlock[2]];  isr[15] = inv_sbox[stateBlock[3]];
                isr[4]  = inv_sbox[stateBlock[4]];  isr[9]  = inv_sbox[stateBlock[5]];
                isr[14] = inv_sbox[stateBlock[6]];  isr[3]  = inv_sbox[stateBlock[7]];
                isr[8]  = inv_sbox[stateBlock[8]];  isr[13] = inv_sbox[stateBlock[9]];
                isr[2]  = inv_sbox[stateBlock[10]]; isr[7]  = inv_sbox[stateBlock[11]];
                isr[12] = inv_sbox[stateBlock[12]]; isr[1]  = inv_sbox[stateBlock[13]];
                isr[6]  = inv_sbox[stateBlock[14]]; isr[11] = inv_sbox[stateBlock[15]];

                // InvMixColumns
                auto xtime = [](uint8_t x) -> uint8_t {
                    return static_cast<uint8_t>((x << 1) ^ ((x >> 7) * 0x1B));
                };
                auto mul = [&xtime](uint8_t a, uint8_t b) -> uint8_t {
                    uint8_t r = 0;
                    uint8_t tmp = a;
                    for (int i = 0; i < 8; ++i) {
                        if (b & 1) r ^= tmp;
                        tmp = xtime(tmp);
                        b >>= 1;
                    }
                    return r;
                };
                for (int col = 0; col < 4; ++col) {
                    uint8_t a0 = isr[col*4], a1 = isr[col*4+1], a2 = isr[col*4+2], a3 = isr[col*4+3];
                    outBlock[col*4]   = mul(a0,0x0E) ^ mul(a1,0x0B) ^ mul(a2,0x0D) ^ mul(a3,0x09);
                    outBlock[col*4+1] = mul(a0,0x09) ^ mul(a1,0x0E) ^ mul(a2,0x0B) ^ mul(a3,0x0D);
                    outBlock[col*4+2] = mul(a0,0x0D) ^ mul(a1,0x09) ^ mul(a2,0x0E) ^ mul(a3,0x0B);
                    outBlock[col*4+3] = mul(a0,0x0B) ^ mul(a1,0x0D) ^ mul(a2,0x09) ^ mul(a3,0x0E);
                }
                for (int i = 0; i < 16; ++i) outBlock[i] ^= keyBlock[i];
                std::memcpy(result.u8 + lane, outBlock, 16);
            }
            return WriteDst(result, origDst);
        }
        case 0xDE: { // VAESENC_LAST
            ZMMValue state, key, result;
            ReadZMM(vvvv, state);
            auto err = ReadSrc(1, key);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            static constexpr uint8_t sbox[256] = {
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
            for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                uint8_t stateBlock[16], keyBlock[16];
                std::memcpy(stateBlock, state.u8 + lane, 16);
                std::memcpy(keyBlock, key.u8 + lane, 16);
                // SubBytes + ShiftRows (no MixColumns for last round)
                uint8_t sr[16];
                sr[0]  = sbox[stateBlock[0]];  sr[1]  = sbox[stateBlock[5]];
                sr[2]  = sbox[stateBlock[10]]; sr[3]  = sbox[stateBlock[15]];
                sr[4]  = sbox[stateBlock[4]];  sr[5]  = sbox[stateBlock[9]];
                sr[6]  = sbox[stateBlock[14]]; sr[7]  = sbox[stateBlock[3]];
                sr[8]  = sbox[stateBlock[8]];  sr[9]  = sbox[stateBlock[13]];
                sr[10] = sbox[stateBlock[2]];  sr[11] = sbox[stateBlock[7]];
                sr[12] = sbox[stateBlock[12]]; sr[13] = sbox[stateBlock[1]];
                sr[14] = sbox[stateBlock[6]];  sr[15] = sbox[stateBlock[11]];
                for (int i = 0; i < 16; ++i) sr[i] ^= keyBlock[i];
                std::memcpy(result.u8 + lane, sr, 16);
            }
            return WriteDst(result, origDst);
        }
        case 0xDF: { // VAESDEC_LAST
            ZMMValue state, key, result;
            ReadZMM(vvvv, state);
            auto err = ReadSrc(1, key);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            static constexpr uint8_t inv_sbox[256] = {
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
            for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                uint8_t stateBlock[16], keyBlock[16], outBlock[16];
                std::memcpy(stateBlock, state.u8 + lane, 16);
                std::memcpy(keyBlock, key.u8 + lane, 16);
                // InvSubBytes + InvShiftRows (no InvMixColumns for last round)
                outBlock[0]  = inv_sbox[stateBlock[0]];  outBlock[13] = inv_sbox[stateBlock[1]];
                outBlock[10] = inv_sbox[stateBlock[2]];  outBlock[7]  = inv_sbox[stateBlock[3]];
                outBlock[4]  = inv_sbox[stateBlock[4]];  outBlock[1]  = inv_sbox[stateBlock[5]];
                outBlock[14] = inv_sbox[stateBlock[6]];  outBlock[11] = inv_sbox[stateBlock[7]];
                outBlock[8]  = inv_sbox[stateBlock[8]];  outBlock[5]  = inv_sbox[stateBlock[9]];
                outBlock[2]  = inv_sbox[stateBlock[10]]; outBlock[15] = inv_sbox[stateBlock[11]];
                outBlock[12] = inv_sbox[stateBlock[12]]; outBlock[9]  = inv_sbox[stateBlock[13]];
                outBlock[6]  = inv_sbox[stateBlock[14]]; outBlock[3]  = inv_sbox[stateBlock[15]];
                for (int i = 0; i < 16; ++i) outBlock[i] ^= keyBlock[i];
                std::memcpy(result.u8 + lane, outBlock, 16);
            }
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // Absolute value: VPABSD (0F38 1E W=0) / VPABSQ (0F38 1F W=1)
        // ----------------------------------------------------------------
        case 0x1E: {
            ZMMValue src, result;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                result.i32[i] = (src.i32[i] < 0) ? -src.i32[i] : src.i32[i];
            return WriteDst(result, origDst);
        }
        case 0x1F: {
            ZMMValue src, result;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                result.i64[i] = (src.i64[i] < 0) ? -src.i64[i] : src.i64[i];
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // Variable shift: VPSRLVD/Q (0F38 45/47), VPSLLVD/Q (0F38 47)
        // ----------------------------------------------------------------
        case 0x45: { // VPSRLVD (W=0) / VPSRLVQ (W=1)
            ZMMValue src, shift, result;
            ReadZMM(vvvv, src);
            auto err = ReadSrc(1, shift);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    uint64_t cnt = shift.u64[i];
                    result.u64[i] = (cnt >= 64) ? 0 : (src.u64[i] >> cnt);
                }
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    uint32_t cnt = shift.u32[i];
                    result.u32[i] = (cnt >= 32) ? 0 : (src.u32[i] >> cnt);
                }
            }
            return WriteDst(result, origDst);
        }
        case 0x47: { // VPSLLVD (W=0) / VPSLLVQ (W=1)
            ZMMValue src, shift, result;
            ReadZMM(vvvv, src);
            auto err = ReadSrc(1, shift);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    uint64_t cnt = shift.u64[i];
                    result.u64[i] = (cnt >= 64) ? 0 : (src.u64[i] << cnt);
                }
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    uint32_t cnt = shift.u32[i];
                    result.u32[i] = (cnt >= 32) ? 0 : (src.u32[i] << cnt);
                }
            }
            return WriteDst(result, origDst);
        }
        case 0x46: { // VPSRAVD (W=0) / VPSRAVQ (W=1) — variable arithmetic shift right
            ZMMValue src, shift, result;
            ReadZMM(vvvv, src);
            auto err = ReadSrc(1, shift);
            if (err != ErrorCode::Success) return err;
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    uint64_t cnt = shift.u64[i];
                    result.i64[i] = (cnt >= 64) ? (src.i64[i] >> 63) : (src.i64[i] >> cnt);
                }
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    uint32_t cnt = shift.u32[i];
                    result.i32[i] = (cnt >= 32) ? (src.i32[i] >> 31) : (src.i32[i] >> cnt);
                }
            }
            return WriteDst(result, origDst);
        }

        // ----------------------------------------------------------------
        // Compress/Expand (0F38 8B / 89)
        // ----------------------------------------------------------------
        case 0x8B: { // VPCOMPRESSD (W=0) / VPCOMPRESSQ (W=1)
            ZMMValue src, result;
            ReadZMM(inst.Op(1).reg.regIndex, src);
            result.Clear();
            uint32_t dst_idx = 0;
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    if ((activeMask >> i) & 1) {
                        result.u64[dst_idx++] = src.u64[i];
                    }
                }
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    if ((activeMask >> i) & 1) {
                        result.u32[dst_idx++] = src.u32[i];
                    }
                }
            }
            // Compress doesn't use standard WriteDst masking
            const auto& dstOp = inst.Op(0);
            if (dstOp.IsRegister()) {
                WriteZMM(dstOp.reg.regIndex, result);
                return ErrorCode::Success;
            }
            if (dstOp.IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(dstOp, inst);
                uint32_t writeBytes = dst_idx * elemBytes;
                return mem.Write(addr, result.u8, writeBytes);
            }
            return ErrorCode::InvalidOperandSize;
        }
        case 0x89: { // VPEXPANDD (W=0) / VPEXPANDQ (W=1)
            ZMMValue src, result;
            result.Clear();
            uint32_t src_idx = 0;
            if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, src.u8, vecLen);
                if (err != ErrorCode::Success) return err;
            } else {
                ReadZMM(inst.Op(1).reg.regIndex, src);
            }
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    if ((activeMask >> i) & 1) {
                        result.u64[i] = src.u64[src_idx++];
                    }
                }
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    if ((activeMask >> i) & 1) {
                        result.u32[i] = src.u32[src_idx++];
                    }
                }
            }
            const auto& dstOp = inst.Op(0);
            if (dstOp.IsRegister()) {
                WriteZMM(dstOp.reg.regIndex, result);
                return ErrorCode::Success;
            }
            return ErrorCode::InvalidOperandSize;
        }

        default:
            break;
        }
    }
    else if (inst.opcodeMap == OpcodeMap::ThreeByte3A) {
        // Map 3 (EVEX 0F 3A)
        switch (op) {
        // ----------------------------------------------------------------
        // VPTERNLOGD/Q (alternate encoding in map 3)
        // ----------------------------------------------------------------
        case 0x25: {
            // Same as map2 case — VPTERNLOGD/Q is in 0F3A per spec
            ZMMValue src1, src2, src3, result;
            ReadZMM(inst.Op(0).reg.regIndex, src1);
            ReadZMM(vvvv, src2);
            auto err = ReadSrc(2, src3);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.Op(3).imm.value);
            result.Clear();
            if (wBit) {
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    uint64_t a = src1.u64[i], b = src2.u64[i], c = src3.u64[i];
                    uint64_t r = 0;
                    for (int bit = 0; bit < 64; ++bit) {
                        uint8_t idx = static_cast<uint8_t>(
                            (((a >> bit) & 1) << 2) | (((b >> bit) & 1) << 1) | ((c >> bit) & 1));
                        r |= static_cast<uint64_t>((imm >> idx) & 1) << bit;
                    }
                    result.u64[i] = r;
                }
            } else {
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    uint32_t a = src1.u32[i], b = src2.u32[i], c = src3.u32[i];
                    uint32_t r = 0;
                    for (int bit = 0; bit < 32; ++bit) {
                        uint8_t idx = static_cast<uint8_t>(
                            (((a >> bit) & 1) << 2) | (((b >> bit) & 1) << 1) | ((c >> bit) & 1));
                        r |= static_cast<uint32_t>((imm >> idx) & 1) << bit;
                    }
                    result.u32[i] = r;
                }
            }
            return WriteDst(result, origDst);
        }

        // Shuffle imm8
        case 0x00: { // VPSHUFB-like with imm — actually VPERMQ imm for EVEX
            ZMMValue src, result;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.Op(2).imm.value);
            result.Clear();
            if (wBit) { // VPERMQ imm
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    uint8_t sel = (imm >> (i * 2)) & 3;
                    result.u64[i] = src.u64[sel];
                }
            }
            return WriteDst(result, origDst);
        }

        // VSHUFPS/PD imm
        case 0x04: { // VPERMILPS imm
            ZMMValue src, result;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.Op(2).imm.value);
            result.Clear();
            for (uint32_t lane = 0; lane < vecLen; lane += 16) {
                auto* r = reinterpret_cast<uint32_t*>(result.u8 + lane);
                auto* s = reinterpret_cast<const uint32_t*>(src.u8 + lane);
                r[0] = s[(imm >> 0) & 3];
                r[1] = s[(imm >> 2) & 3];
                r[2] = s[(imm >> 4) & 3];
                r[3] = s[(imm >> 6) & 3];
            }
            return WriteDst(result, origDst);
        }

        // VALIGNQ / VALIGND (0F3A 03)
        case 0x03: {
            ZMMValue src1, src2, result;
            ReadZMM(vvvv, src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.Op(2).imm.value);
            result.Clear();
            if (wBit) { // VALIGNQ
                uint32_t count = vecLen / 8;
                uint8_t shift = imm & (count * 2 - 1);
                // Concatenate src2:src1 and extract starting at shift
                for (uint32_t i = 0; i < count; ++i) {
                    uint32_t idx = i + shift;
                    if (idx < count) result.u64[i] = src1.u64[idx];
                    else result.u64[i] = src2.u64[idx - count];
                }
            } else { // VALIGND
                uint32_t count = vecLen / 4;
                uint8_t shift = imm & (count * 2 - 1);
                for (uint32_t i = 0; i < count; ++i) {
                    uint32_t idx = i + shift;
                    if (idx < count) result.u32[i] = src1.u32[idx];
                    else result.u32[i] = src2.u32[idx - count];
                }
            }
            return WriteDst(result, origDst);
        }

        default:
            break;
        }
    }

    // Unsupported EVEX instruction — report for anti-evasion logging
    return ErrorCode::UnsupportedOpcode;
}

} // namespace Phantom
