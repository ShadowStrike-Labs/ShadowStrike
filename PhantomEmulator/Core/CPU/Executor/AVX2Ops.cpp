/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AVX2Ops.cpp — AVX2 (256-bit) instruction executor
 *
 * Implements CPU::ExecuteAVX2 for VEX-encoded 256-bit integer and
 * logical instructions. Handles both VEX.L=0 (128-bit with upper
 * YMM zeroing) and VEX.L=1 (full 256-bit) forms.
 *
 * Modern malware heavily uses AVX2 for fast encryption, obfuscated
 * string ops, and anti-emulation detection. Correctness here is
 * critical to prevent sandbox evasion.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "AVX2Ops.hpp"
#include <cstring>
#include <algorithm>

namespace Phantom {

// ============================================================================
// AVX2 Instruction Handler
// ============================================================================

ErrorCode CPU::ExecuteAVX2(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (!inst.prefixes.hasVEX) return ErrorCode::UnimplementedOpcode;

    const uint8_t op      = inst.opcode;
    const uint8_t vexL    = inst.prefixes.vexL;
    const uint8_t vexPP   = inst.prefixes.vexPP;
    const uint8_t vexMap  = inst.prefixes.vexMMMMM;
    const uint8_t vvvv    = static_cast<uint8_t>(15 - inst.prefixes.vexVVVV);
    const bool    is256   = (vexL == 1);
    const uint32_t vecLen = is256 ? 32u : 16u;

    // ====================================================================
    // Helper: Read a YMM/XMM source from an operand (register or memory)
    // ====================================================================
    auto ReadSrc = [&](uint8_t opIdx, YMMValue& out) -> ErrorCode {
        out.Clear();
        if (inst.Op(opIdx).IsRegister()) {
            if (is256) {
                m_state.GetYMM(inst.Op(opIdx).reg.regIndex, out.u8);
            } else {
                std::memcpy(out.u8, m_state.XMM(inst.Op(opIdx).reg.regIndex).u8, 16);
            }
            return ErrorCode::Success;
        }
        if (inst.Op(opIdx).IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(opIdx), inst);
            return mem.Read(addr, out.u8, vecLen);
        }
        return ErrorCode::InvalidOperandSize;
    };

    // Helper: Read source from vexVVVV register
    auto ReadVvvv = [&](YMMValue& out) noexcept {
        out.Clear();
        if (is256) {
            m_state.GetYMM(vvvv, out.u8);
        } else {
            std::memcpy(out.u8, m_state.XMM(vvvv).u8, 16);
        }
    };

    // Helper: Write result to destination Op(0)
    auto WriteDst = [&](const YMMValue& val) noexcept {
        uint8_t dstIdx = inst.Op(0).reg.regIndex;
        if (is256) {
            m_state.SetYMM(dstIdx, val.u8);
        } else {
            std::memcpy(m_state.XMM(dstIdx).u8, val.u8, 16);
            m_state.ClearYMMHigh(dstIdx);
        }
    };

    // Helper: Write result to destination Op(0) for store-form (Op(0) may be memory)
    auto WriteStore = [&](const YMMValue& val) -> ErrorCode {
        if (inst.Op(0).IsRegister()) {
            WriteDst(val);
            return ErrorCode::Success;
        }
        if (inst.Op(0).IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            return mem.Write(addr, val.u8, vecLen);
        }
        return ErrorCode::InvalidOperandSize;
    };

    // ====================================================================
    // MAP 0F (vexMMMMM=1)
    // ====================================================================
    if (vexMap == 1) {

        // ================================================================
        // VXORPS (0F 57, PP=0) — 256/128-bit XOR
        // ================================================================
        if (op == 0x57 && vexPP == 0) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                reinterpret_cast<uint64_t*>(dst.u8)[i] =
                    reinterpret_cast<const uint64_t*>(src1.u8)[i] ^
                    reinterpret_cast<const uint64_t*>(src2.u8)[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VANDPS (0F 54, PP=0) — 256/128-bit AND
        // ================================================================
        if (op == 0x54 && vexPP == 0) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                reinterpret_cast<uint64_t*>(dst.u8)[i] =
                    reinterpret_cast<const uint64_t*>(src1.u8)[i] &
                    reinterpret_cast<const uint64_t*>(src2.u8)[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VANDNPS (0F 55, PP=0) — 256/128-bit ANDN (~src1 & src2)
        // ================================================================
        if (op == 0x55 && vexPP == 0) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                reinterpret_cast<uint64_t*>(dst.u8)[i] =
                    ~reinterpret_cast<const uint64_t*>(src1.u8)[i] &
                     reinterpret_cast<const uint64_t*>(src2.u8)[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VORPS (0F 56, PP=0) — 256/128-bit OR
        // ================================================================
        if (op == 0x56 && vexPP == 0) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 8; ++i)
                reinterpret_cast<uint64_t*>(dst.u8)[i] =
                    reinterpret_cast<const uint64_t*>(src1.u8)[i] |
                    reinterpret_cast<const uint64_t*>(src2.u8)[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VMOVDQA (0F 6F, PP=1) — Aligned load
        // ================================================================
        if (op == 0x6F && vexPP == 1) {
            YMMValue val{};
            if (inst.Op(1).IsRegister()) {
                if (is256)
                    m_state.GetYMM(inst.Op(1).reg.regIndex, val.u8);
                else
                    std::memcpy(val.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                if (is256 && (addr & 0x1F)) return ErrorCode::UnalignedAccess;
                if (!is256 && (addr & 0x0F)) return ErrorCode::UnalignedAccess;
                auto err = mem.Read(addr, val.u8, vecLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            WriteDst(val);
            return ErrorCode::Success;
        }

        // ================================================================
        // VMOVDQA (0F 7F, PP=1) — Aligned store
        // ================================================================
        if (op == 0x7F && vexPP == 1) {
            YMMValue val{};
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (is256)
                m_state.GetYMM(srcIdx, val.u8);
            else
                std::memcpy(val.u8, m_state.XMM(srcIdx).u8, 16);

            if (inst.Op(0).IsRegister()) {
                WriteDst(val);
            } else if (inst.Op(0).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                if (is256 && (addr & 0x1F)) return ErrorCode::UnalignedAccess;
                if (!is256 && (addr & 0x0F)) return ErrorCode::UnalignedAccess;
                auto err = mem.Write(addr, val.u8, vecLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            return ErrorCode::Success;
        }

        // ================================================================
        // VMOVUPS (0F 10, PP=0) — Unaligned load
        // ================================================================
        if (op == 0x10 && vexPP == 0) {
            YMMValue val{};
            auto err = ReadSrc(1, val);
            if (err != ErrorCode::Success) return err;
            WriteDst(val);
            return ErrorCode::Success;
        }

        // ================================================================
        // VMOVUPS (0F 11, PP=0) — Unaligned store
        // ================================================================
        if (op == 0x11 && vexPP == 0) {
            YMMValue val{};
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (is256)
                m_state.GetYMM(srcIdx, val.u8);
            else
                std::memcpy(val.u8, m_state.XMM(srcIdx).u8, 16);
            return WriteStore(val);
        }

        // ================================================================
        // PP=1 (66 prefix) integer ops — Map 0F
        // ================================================================
        if (vexPP == 1) {

            // ============================================================
            // VPADDQ (66 0F D4) — Add packed qwords
            // ============================================================
            if (op == 0xD4) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    dst.u64[i] = src1.u64[i] + src2.u64[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPMULLW (66 0F D5) — Multiply packed words, low result
            // ============================================================
            if (op == 0xD5) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 2; ++i)
                    dst.u16[i] = static_cast<uint16_t>(
                        static_cast<int32_t>(src1.i16[i]) * static_cast<int32_t>(src2.i16[i]));
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPAND (66 0F DB) — AND packed integers
            // ============================================================
            if (op == 0xDB) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    dst.u64[i] = src1.u64[i] & src2.u64[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPANDN (66 0F DF) — AND-NOT packed integers
            // ============================================================
            if (op == 0xDF) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    dst.u64[i] = ~src1.u64[i] & src2.u64[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPOR (66 0F EB) — OR packed integers
            // ============================================================
            if (op == 0xEB) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    dst.u64[i] = src1.u64[i] | src2.u64[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPXOR (66 0F EF) — XOR packed integers
            // ============================================================
            if (op == 0xEF) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    dst.u64[i] = src1.u64[i] ^ src2.u64[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPADDB (66 0F FC) — Add packed bytes
            // ============================================================
            if (op == 0xFC) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen; ++i)
                    dst.u8[i] = src1.u8[i] + src2.u8[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPADDW (66 0F FD) — Add packed words
            // ============================================================
            if (op == 0xFD) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 2; ++i)
                    dst.u16[i] = src1.u16[i] + src2.u16[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPADDD (66 0F FE) — Add packed dwords
            // ============================================================
            if (op == 0xFE) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    dst.u32[i] = src1.u32[i] + src2.u32[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPSUBB (66 0F F8) — Subtract packed bytes
            // ============================================================
            if (op == 0xF8) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen; ++i)
                    dst.u8[i] = src1.u8[i] - src2.u8[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPSUBW (66 0F F9) — Subtract packed words
            // ============================================================
            if (op == 0xF9) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 2; ++i)
                    dst.u16[i] = src1.u16[i] - src2.u16[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPSUBD (66 0F FA) — Subtract packed dwords
            // ============================================================
            if (op == 0xFA) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    dst.u32[i] = src1.u32[i] - src2.u32[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPSUBQ (66 0F FB) — Subtract packed qwords
            // ============================================================
            if (op == 0xFB) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 8; ++i)
                    dst.u64[i] = src1.u64[i] - src2.u64[i];
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPCMPEQB (66 0F 74) — Compare equal packed bytes
            // ============================================================
            if (op == 0x74) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen; ++i)
                    dst.u8[i] = (src1.u8[i] == src2.u8[i]) ? 0xFF : 0x00;
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPCMPEQW (66 0F 75) — Compare equal packed words
            // ============================================================
            if (op == 0x75) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 2; ++i)
                    dst.u16[i] = (src1.u16[i] == src2.u16[i]) ? 0xFFFF : 0x0000;
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPCMPEQD (66 0F 76) — Compare equal packed dwords
            // ============================================================
            if (op == 0x76) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    dst.u32[i] = (src1.u32[i] == src2.u32[i]) ? 0xFFFFFFFFu : 0x00000000u;
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPCMPGTB (66 0F 64) — Compare greater than signed bytes
            // ============================================================
            if (op == 0x64) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen; ++i)
                    dst.u8[i] = (src1.i8[i] > src2.i8[i]) ? 0xFF : 0x00;
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPCMPGTW (66 0F 65) — Compare greater than signed words
            // ============================================================
            if (op == 0x65) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 2; ++i)
                    dst.u16[i] = (src1.i16[i] > src2.i16[i]) ? 0xFFFF : 0x0000;
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPCMPGTD (66 0F 66) — Compare greater than signed dwords
            // ============================================================
            if (op == 0x66) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 4; ++i)
                    dst.u32[i] = (src1.i32[i] > src2.i32[i]) ? 0xFFFFFFFFu : 0x00000000u;
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPSHUFD (66 0F 70) — Shuffle packed dwords by imm8
            // Per-lane: each 128-bit lane is shuffled independently
            // ============================================================
            if (op == 0x70) {
                YMMValue src{}, dst{};
                auto err = ReadSrc(1, src);
                if (err != ErrorCode::Success) return err;
                uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t base = lane * 4;
                    dst.u32[base + 0] = src.u32[base + ((imm >> 0) & 3)];
                    dst.u32[base + 1] = src.u32[base + ((imm >> 2) & 3)];
                    dst.u32[base + 2] = src.u32[base + ((imm >> 4) & 3)];
                    dst.u32[base + 3] = src.u32[base + ((imm >> 6) & 3)];
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // Shift words/dwords/qwords by immediate (66 0F 71/72/73)
            // These are group opcodes — opcodeExt selects the operation:
            //   /2 = VPSRL  /4 = VPSRA  /6 = VPSLL
            // ============================================================
            if (op == 0x71) {
                // VPS{R,A,L}LW — shift words by imm8
                YMMValue src{}, dst{};
                ReadVvvv(src);
                uint8_t count = static_cast<uint8_t>(inst.immediate & 0xFF);
                uint8_t ext = inst.opcodeExt;
                for (uint32_t i = 0; i < vecLen / 2; ++i) {
                    if (ext == 2)       // VPSRLW
                        dst.u16[i] = (count >= 16) ? 0 : (src.u16[i] >> count);
                    else if (ext == 4)  // VPSRAW
                        dst.i16[i] = (count >= 16)
                            ? static_cast<int16_t>(src.i16[i] >> 15)
                            : static_cast<int16_t>(src.i16[i] >> count);
                    else if (ext == 6)  // VPSLLW
                        dst.u16[i] = (count >= 16) ? 0 : static_cast<uint16_t>(src.u16[i] << count);
                    else
                        return ErrorCode::UnimplementedOpcode;
                }
                // Dest is written to vexVVVV for immediate group shifts
                uint8_t dstIdx = vvvv;
                if (is256)
                    m_state.SetYMM(dstIdx, dst.u8);
                else {
                    std::memcpy(m_state.XMM(dstIdx).u8, dst.u8, 16);
                    m_state.ClearYMMHigh(dstIdx);
                }
                return ErrorCode::Success;
            }

            if (op == 0x72) {
                // VPS{R,A,L}LD — shift dwords by imm8
                YMMValue src{}, dst{};
                ReadVvvv(src);
                uint8_t count = static_cast<uint8_t>(inst.immediate & 0xFF);
                uint8_t ext = inst.opcodeExt;
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    if (ext == 2)       // VPSRLD
                        dst.u32[i] = (count >= 32) ? 0 : (src.u32[i] >> count);
                    else if (ext == 4)  // VPSRAD
                        dst.i32[i] = (count >= 32)
                            ? (src.i32[i] >> 31)
                            : (src.i32[i] >> count);
                    else if (ext == 6)  // VPSLLD
                        dst.u32[i] = (count >= 32) ? 0 : (src.u32[i] << count);
                    else
                        return ErrorCode::UnimplementedOpcode;
                }
                uint8_t dstIdx = vvvv;
                if (is256)
                    m_state.SetYMM(dstIdx, dst.u8);
                else {
                    std::memcpy(m_state.XMM(dstIdx).u8, dst.u8, 16);
                    m_state.ClearYMMHigh(dstIdx);
                }
                return ErrorCode::Success;
            }

            if (op == 0x73) {
                // VPS{R,L}LQ — shift qwords by imm8
                YMMValue src{}, dst{};
                ReadVvvv(src);
                uint8_t count = static_cast<uint8_t>(inst.immediate & 0xFF);
                uint8_t ext = inst.opcodeExt;
                for (uint32_t i = 0; i < vecLen / 8; ++i) {
                    if (ext == 2)       // VPSRLQ
                        dst.u64[i] = (count >= 64) ? 0 : (src.u64[i] >> count);
                    else if (ext == 3)  // VPSRLDQ (byte shift right whole 128-bit lane)
                    {
                        uint32_t lane = i / 2;
                        uint32_t laneBase = lane * 16;
                        uint8_t laneBytes[16];
                        std::memcpy(laneBytes, src.u8 + laneBase, 16);
                        uint8_t shifted[16]{};
                        if (count < 16) {
                            std::memcpy(shifted, laneBytes + count, 16 - count);
                        }
                        std::memcpy(dst.u8 + laneBase, shifted, 16);
                        // Skip the second qword of this lane (already handled)
                        if ((i & 1) == 0) ++i;
                        continue;
                    }
                    else if (ext == 6)  // VPSLLQ
                        dst.u64[i] = (count >= 64) ? 0 : (src.u64[i] << count);
                    else if (ext == 7)  // VPSLLDQ (byte shift left whole 128-bit lane)
                    {
                        uint32_t lane = i / 2;
                        uint32_t laneBase = lane * 16;
                        uint8_t laneBytes[16];
                        std::memcpy(laneBytes, src.u8 + laneBase, 16);
                        uint8_t shifted[16]{};
                        if (count < 16) {
                            std::memcpy(shifted + count, laneBytes, 16 - count);
                        }
                        std::memcpy(dst.u8 + laneBase, shifted, 16);
                        if ((i & 1) == 0) ++i;
                        continue;
                    }
                    else
                        return ErrorCode::UnimplementedOpcode;
                }
                uint8_t dstIdx = vvvv;
                if (is256)
                    m_state.SetYMM(dstIdx, dst.u8);
                else {
                    std::memcpy(m_state.XMM(dstIdx).u8, dst.u8, 16);
                    m_state.ClearYMMHigh(dstIdx);
                }
                return ErrorCode::Success;
            }

            // ============================================================
            // Shift by XMM count (66 0F D1/D2/D3/E1/E2/F1/F2/F3)
            // Shift count from low 64-bits of Op(1) XMM
            // ============================================================
            if (op == 0xD1 || op == 0xD2 || op == 0xD3 ||
                op == 0xE1 || op == 0xE2 ||
                op == 0xF1 || op == 0xF2 || op == 0xF3) {

                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;

                // Shift count from low 64 bits of src2
                uint64_t count = src2.u64[0];

                switch (op) {
                    case 0xD1: // VPSRLW
                        for (uint32_t i = 0; i < vecLen / 2; ++i)
                            dst.u16[i] = (count >= 16) ? 0 : (src1.u16[i] >> count);
                        break;
                    case 0xD2: // VPSRLD
                        for (uint32_t i = 0; i < vecLen / 4; ++i)
                            dst.u32[i] = (count >= 32) ? 0 : (src1.u32[i] >> static_cast<uint32_t>(count));
                        break;
                    case 0xD3: // VPSRLQ
                        for (uint32_t i = 0; i < vecLen / 8; ++i)
                            dst.u64[i] = (count >= 64) ? 0 : (src1.u64[i] >> count);
                        break;
                    case 0xE1: // VPSRAW
                        for (uint32_t i = 0; i < vecLen / 2; ++i)
                            dst.i16[i] = (count >= 16)
                                ? static_cast<int16_t>(src1.i16[i] >> 15)
                                : static_cast<int16_t>(src1.i16[i] >> count);
                        break;
                    case 0xE2: // VPSRAD
                        for (uint32_t i = 0; i < vecLen / 4; ++i)
                            dst.i32[i] = (count >= 32)
                                ? (src1.i32[i] >> 31)
                                : (src1.i32[i] >> static_cast<int>(count));
                        break;
                    case 0xF1: // VPSLLW
                        for (uint32_t i = 0; i < vecLen / 2; ++i)
                            dst.u16[i] = (count >= 16) ? 0 : static_cast<uint16_t>(src1.u16[i] << count);
                        break;
                    case 0xF2: // VPSLLD
                        for (uint32_t i = 0; i < vecLen / 4; ++i)
                            dst.u32[i] = (count >= 32) ? 0 : (src1.u32[i] << static_cast<uint32_t>(count));
                        break;
                    case 0xF3: // VPSLLQ
                        for (uint32_t i = 0; i < vecLen / 8; ++i)
                            dst.u64[i] = (count >= 64) ? 0 : (src1.u64[i] << count);
                        break;
                    default:
                        return ErrorCode::UnimplementedOpcode;
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKLBW (66 0F 60) — Unpack and interleave low bytes
            // Per-lane: low 8 bytes of each 128-bit lane interleaved
            // ============================================================
            if (op == 0x60) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 16;
                    for (uint32_t i = 0; i < 8; ++i) {
                        dst.u8[lbase + i * 2 + 0] = src1.u8[lbase + i];
                        dst.u8[lbase + i * 2 + 1] = src2.u8[lbase + i];
                    }
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKLWD (66 0F 61) — Unpack and interleave low words
            // ============================================================
            if (op == 0x61) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 8; // in uint16_t units: 8 per 128-bit lane
                    for (uint32_t i = 0; i < 4; ++i) {
                        dst.u16[lbase + i * 2 + 0] = src1.u16[lbase + i];
                        dst.u16[lbase + i * 2 + 1] = src2.u16[lbase + i];
                    }
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKLDQ (66 0F 62) — Unpack and interleave low dwords
            // ============================================================
            if (op == 0x62) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 4; // in uint32_t units
                    dst.u32[lbase + 0] = src1.u32[lbase + 0];
                    dst.u32[lbase + 1] = src2.u32[lbase + 0];
                    dst.u32[lbase + 2] = src1.u32[lbase + 1];
                    dst.u32[lbase + 3] = src2.u32[lbase + 1];
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKLQDQ (66 0F 6C) — Unpack and interleave low qwords
            // ============================================================
            if (op == 0x6C) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 2;
                    dst.u64[lbase + 0] = src1.u64[lbase + 0];
                    dst.u64[lbase + 1] = src2.u64[lbase + 0];
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKHBW (66 0F 68) — Unpack and interleave high bytes
            // ============================================================
            if (op == 0x68) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 16;
                    for (uint32_t i = 0; i < 8; ++i) {
                        dst.u8[lbase + i * 2 + 0] = src1.u8[lbase + 8 + i];
                        dst.u8[lbase + i * 2 + 1] = src2.u8[lbase + 8 + i];
                    }
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKHWD (66 0F 69) — Unpack and interleave high words
            // ============================================================
            if (op == 0x69) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 8;
                    for (uint32_t i = 0; i < 4; ++i) {
                        dst.u16[lbase + i * 2 + 0] = src1.u16[lbase + 4 + i];
                        dst.u16[lbase + i * 2 + 1] = src2.u16[lbase + 4 + i];
                    }
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKHDQ (66 0F 6A) — Unpack and interleave high dwords
            // ============================================================
            if (op == 0x6A) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 4;
                    dst.u32[lbase + 0] = src1.u32[lbase + 2];
                    dst.u32[lbase + 1] = src2.u32[lbase + 2];
                    dst.u32[lbase + 2] = src1.u32[lbase + 3];
                    dst.u32[lbase + 3] = src2.u32[lbase + 3];
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPUNPCKHQDQ (66 0F 6D) — Unpack and interleave high qwords
            // ============================================================
            if (op == 0x6D) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                uint32_t lanes = vecLen / 16;
                for (uint32_t lane = 0; lane < lanes; ++lane) {
                    uint32_t lbase = lane * 2;
                    dst.u64[lbase + 0] = src1.u64[lbase + 1];
                    dst.u64[lbase + 1] = src2.u64[lbase + 1];
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPMULHUW (66 0F E4) — Multiply packed unsigned words, high
            // ============================================================
            if (op == 0xE4) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 2; ++i) {
                    uint32_t prod = static_cast<uint32_t>(src1.u16[i]) *
                                    static_cast<uint32_t>(src2.u16[i]);
                    dst.u16[i] = static_cast<uint16_t>(prod >> 16);
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPMULHW (66 0F E5) — Multiply packed signed words, high
            // ============================================================
            if (op == 0xE5) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 2; ++i) {
                    int32_t prod = static_cast<int32_t>(src1.i16[i]) *
                                   static_cast<int32_t>(src2.i16[i]);
                    dst.i16[i] = static_cast<int16_t>(static_cast<uint32_t>(prod) >> 16);
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

            // ============================================================
            // VPMADDWD (66 0F F5) — Multiply and add packed words to dwords
            // ============================================================
            if (op == 0xF5) {
                YMMValue src1{}, src2{}, dst{};
                ReadVvvv(src1);
                auto err = ReadSrc(1, src2);
                if (err != ErrorCode::Success) return err;
                for (uint32_t i = 0; i < vecLen / 4; ++i) {
                    int32_t lo = static_cast<int32_t>(src1.i16[i * 2 + 0]) *
                                 static_cast<int32_t>(src2.i16[i * 2 + 0]);
                    int32_t hi = static_cast<int32_t>(src1.i16[i * 2 + 1]) *
                                 static_cast<int32_t>(src2.i16[i * 2 + 1]);
                    dst.i32[i] = lo + hi;
                }
                WriteDst(dst);
                return ErrorCode::Success;
            }

        } // end vexPP==1 for Map 0F
    } // end vexMap==1

    // ====================================================================
    // MAP 0F38 (vexMMMMM=2)
    // ====================================================================
    if (vexMap == 2 && vexPP == 1) {

        // ================================================================
        // VPSHUFB (0F38 00) — Packed shuffle bytes (per lane)
        // ================================================================
        if (op == 0x00) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            uint32_t lanes = vecLen / 16;
            for (uint32_t lane = 0; lane < lanes; ++lane) {
                uint32_t lbase = lane * 16;
                for (uint32_t i = 0; i < 16; ++i) {
                    uint8_t idx = src2.u8[lbase + i];
                    dst.u8[lbase + i] = (idx & 0x80) ? 0 : src1.u8[lbase + (idx & 0x0F)];
                }
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPHADDW (0F38 01) — Packed horizontal add words (per lane)
        // ================================================================
        if (op == 0x01) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            uint32_t lanes = vecLen / 16;
            for (uint32_t lane = 0; lane < lanes; ++lane) {
                uint32_t wbase = lane * 8;
                // Lower half from src1
                dst.i16[wbase + 0] = static_cast<int16_t>(src1.i16[wbase + 0] + src1.i16[wbase + 1]);
                dst.i16[wbase + 1] = static_cast<int16_t>(src1.i16[wbase + 2] + src1.i16[wbase + 3]);
                dst.i16[wbase + 2] = static_cast<int16_t>(src1.i16[wbase + 4] + src1.i16[wbase + 5]);
                dst.i16[wbase + 3] = static_cast<int16_t>(src1.i16[wbase + 6] + src1.i16[wbase + 7]);
                // Upper half from src2
                dst.i16[wbase + 4] = static_cast<int16_t>(src2.i16[wbase + 0] + src2.i16[wbase + 1]);
                dst.i16[wbase + 5] = static_cast<int16_t>(src2.i16[wbase + 2] + src2.i16[wbase + 3]);
                dst.i16[wbase + 6] = static_cast<int16_t>(src2.i16[wbase + 4] + src2.i16[wbase + 5]);
                dst.i16[wbase + 7] = static_cast<int16_t>(src2.i16[wbase + 6] + src2.i16[wbase + 7]);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMADDUBSW (0F38 04) — Multiply unsigned/signed bytes, add to words
        // ================================================================
        if (op == 0x04) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 2; ++i) {
                int32_t prod0 = static_cast<int32_t>(src1.u8[i * 2 + 0]) *
                                static_cast<int32_t>(src2.i8[i * 2 + 0]);
                int32_t prod1 = static_cast<int32_t>(src1.u8[i * 2 + 1]) *
                                static_cast<int32_t>(src2.i8[i * 2 + 1]);
                int32_t sum = prod0 + prod1;
                // Saturate to int16
                if (sum > 32767) sum = 32767;
                if (sum < -32768) sum = -32768;
                dst.i16[i] = static_cast<int16_t>(sum);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPSIGNB (0F38 08) — Packed sign bytes
        // ================================================================
        if (op == 0x08) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen; ++i) {
                if (src2.i8[i] < 0)
                    dst.i8[i] = static_cast<int8_t>(-static_cast<int16_t>(src1.i8[i]));
                else if (src2.i8[i] == 0)
                    dst.i8[i] = 0;
                else
                    dst.i8[i] = src1.i8[i];
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMULHRSW (0F38 0B) — Multiply high with round and scale, words
        // ================================================================
        if (op == 0x0B) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 2; ++i) {
                int32_t prod = static_cast<int32_t>(src1.i16[i]) *
                               static_cast<int32_t>(src2.i16[i]);
                // (prod >> 14) + 1) >> 1 — round-and-scale
                int32_t tmp = ((prod >> 14) + 1) >> 1;
                if (tmp > 32767) tmp = 32767;
                if (tmp < -32768) tmp = -32768;
                dst.i16[i] = static_cast<int16_t>(tmp);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPABSB (0F38 1C) — Packed absolute value bytes
        // ================================================================
        if (op == 0x1C) {
            YMMValue src{}, dst{};
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen; ++i) {
                int16_t v = src.i8[i];
                dst.u8[i] = static_cast<uint8_t>(v < 0 ? -v : v);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPABSW (0F38 1D) — Packed absolute value words
        // ================================================================
        if (op == 0x1D) {
            YMMValue src{}, dst{};
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 2; ++i) {
                int32_t v = src.i16[i];
                dst.u16[i] = static_cast<uint16_t>(v < 0 ? -v : v);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPABSD (0F38 1E) — Packed absolute value dwords
        // ================================================================
        if (op == 0x1E) {
            YMMValue src{}, dst{};
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                int64_t v = src.i32[i];
                dst.u32[i] = static_cast<uint32_t>(v < 0 ? -v : v);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMOVSXBW (0F38 20) — Sign-extend packed bytes to words
        // Source is half-width: 128-bit for L=1, 64-bit for L=0
        // ================================================================
        if (op == 0x20) {
            YMMValue src{}, dst{};
            // Source is half the destination width
            if (inst.Op(1).IsRegister()) {
                std::memcpy(src.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                uint32_t readLen = is256 ? 16u : 8u;
                auto err = mem.Read(addr, src.u8, readLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            uint32_t count = vecLen / 2;
            for (uint32_t i = 0; i < count; ++i)
                dst.i16[i] = static_cast<int16_t>(src.i8[i]);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMOVSXWD (0F38 23) — Sign-extend packed words to dwords
        // ================================================================
        if (op == 0x23) {
            YMMValue src{}, dst{};
            if (inst.Op(1).IsRegister()) {
                std::memcpy(src.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                uint32_t readLen = is256 ? 16u : 8u;
                auto err = mem.Read(addr, src.u8, readLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            uint32_t count = vecLen / 4;
            for (uint32_t i = 0; i < count; ++i)
                dst.i32[i] = static_cast<int32_t>(src.i16[i]);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMOVSXDQ (0F38 25) — Sign-extend packed dwords to qwords
        // ================================================================
        if (op == 0x25) {
            YMMValue src{}, dst{};
            if (inst.Op(1).IsRegister()) {
                std::memcpy(src.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                uint32_t readLen = is256 ? 16u : 8u;
                auto err = mem.Read(addr, src.u8, readLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            uint32_t count = vecLen / 8;
            for (uint32_t i = 0; i < count; ++i)
                dst.i64[i] = static_cast<int64_t>(src.i32[i]);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMOVZXBW (0F38 30) — Zero-extend packed bytes to words
        // ================================================================
        if (op == 0x30) {
            YMMValue src{}, dst{};
            if (inst.Op(1).IsRegister()) {
                std::memcpy(src.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                uint32_t readLen = is256 ? 16u : 8u;
                auto err = mem.Read(addr, src.u8, readLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            uint32_t count = vecLen / 2;
            for (uint32_t i = 0; i < count; ++i)
                dst.u16[i] = static_cast<uint16_t>(src.u8[i]);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMOVZXWD (0F38 33) — Zero-extend packed words to dwords
        // ================================================================
        if (op == 0x33) {
            YMMValue src{}, dst{};
            if (inst.Op(1).IsRegister()) {
                std::memcpy(src.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                uint32_t readLen = is256 ? 16u : 8u;
                auto err = mem.Read(addr, src.u8, readLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            uint32_t count = vecLen / 4;
            for (uint32_t i = 0; i < count; ++i)
                dst.u32[i] = static_cast<uint32_t>(src.u16[i]);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMOVZXDQ (0F38 35) — Zero-extend packed dwords to qwords
        // ================================================================
        if (op == 0x35) {
            YMMValue src{}, dst{};
            if (inst.Op(1).IsRegister()) {
                std::memcpy(src.u8, m_state.XMM(inst.Op(1).reg.regIndex).u8, 16);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                uint32_t readLen = is256 ? 16u : 8u;
                auto err = mem.Read(addr, src.u8, readLen);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            uint32_t count = vecLen / 8;
            for (uint32_t i = 0; i < count; ++i)
                dst.u64[i] = static_cast<uint64_t>(src.u32[i]);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPERMD (0F38 36) — Permute dwords across full 256-bit vector
        // Only valid for vexL=1
        // ================================================================
        if (op == 0x36) {
            if (!is256) return ErrorCode::UnimplementedOpcode;
            YMMValue idx{}, src{}, dst{};
            ReadVvvv(idx);
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < 8; ++i)
                dst.u32[i] = src.u32[idx.u32[i] & 7];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMINSB (0F38 38) — Packed minimum signed bytes
        // ================================================================
        if (op == 0x38) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen; ++i)
                dst.i8[i] = (src1.i8[i] < src2.i8[i]) ? src1.i8[i] : src2.i8[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMINSD (0F38 39) — Packed minimum signed dwords
        // ================================================================
        if (op == 0x39) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                dst.i32[i] = (src1.i32[i] < src2.i32[i]) ? src1.i32[i] : src2.i32[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMINUW (0F38 3A) — Packed minimum unsigned words
        // ================================================================
        if (op == 0x3A) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 2; ++i)
                dst.u16[i] = (src1.u16[i] < src2.u16[i]) ? src1.u16[i] : src2.u16[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMINUD (0F38 3B) — Packed minimum unsigned dwords
        // ================================================================
        if (op == 0x3B) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                dst.u32[i] = (src1.u32[i] < src2.u32[i]) ? src1.u32[i] : src2.u32[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMAXSB (0F38 3C) — Packed maximum signed bytes
        // ================================================================
        if (op == 0x3C) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen; ++i)
                dst.i8[i] = (src1.i8[i] > src2.i8[i]) ? src1.i8[i] : src2.i8[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMAXSD (0F38 3D) — Packed maximum signed dwords
        // ================================================================
        if (op == 0x3D) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                dst.i32[i] = (src1.i32[i] > src2.i32[i]) ? src1.i32[i] : src2.i32[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMAXUW (0F38 3E) — Packed maximum unsigned words
        // ================================================================
        if (op == 0x3E) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 2; ++i)
                dst.u16[i] = (src1.u16[i] > src2.u16[i]) ? src1.u16[i] : src2.u16[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMAXUD (0F38 3F) — Packed maximum unsigned dwords
        // ================================================================
        if (op == 0x3F) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                dst.u32[i] = (src1.u32[i] > src2.u32[i]) ? src1.u32[i] : src2.u32[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPSRLVD (0F38 45) — Variable shift right logical dwords
        // ================================================================
        if (op == 0x45) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                uint32_t count = src2.u32[i];
                dst.u32[i] = (count >= 32) ? 0 : (src1.u32[i] >> count);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPSRAVD (0F38 46) — Variable shift right arithmetic dwords
        // ================================================================
        if (op == 0x46) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                uint32_t count = src2.u32[i];
                dst.i32[i] = (count >= 32)
                    ? (src1.i32[i] >> 31)
                    : (src1.i32[i] >> count);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPSLLVD (0F38 47) — Variable shift left logical dwords
        // ================================================================
        if (op == 0x47) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                uint32_t count = src2.u32[i];
                dst.u32[i] = (count >= 32) ? 0 : (src1.u32[i] << count);
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPBROADCASTD (0F38 58) — Broadcast dword to all lanes
        // Source is a single dword from XMM[0] or memory dword
        // ================================================================
        if (op == 0x58) {
            uint32_t val = 0;
            if (inst.Op(1).IsRegister()) {
                val = m_state.XMM(inst.Op(1).reg.regIndex).u32[0];
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, &val, 4);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            YMMValue dst{};
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                dst.u32[i] = val;
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPBROADCASTB (0F38 78) — Broadcast byte to all lanes
        // ================================================================
        if (op == 0x78) {
            uint8_t val = 0;
            if (inst.Op(1).IsRegister()) {
                val = m_state.XMM(inst.Op(1).reg.regIndex).u8[0];
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, &val, 1);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            YMMValue dst{};
            std::memset(dst.u8, val, vecLen);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPBROADCASTW (0F38 79) — Broadcast word to all lanes
        // ================================================================
        if (op == 0x79) {
            uint16_t val = 0;
            if (inst.Op(1).IsRegister()) {
                val = m_state.XMM(inst.Op(1).reg.regIndex).u16[0];
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, &val, 2);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            YMMValue dst{};
            for (uint32_t i = 0; i < vecLen / 2; ++i)
                dst.u16[i] = val;
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMASKMOVD (0F38 8C) — Conditional load dwords (masked)
        // Loads from memory only where mask bit 31 is set
        // ================================================================
        if (op == 0x8C) {
            if (!inst.Op(1).IsMemory()) return ErrorCode::InvalidOperandSize;
            YMMValue mask{}, dst{};
            ReadVvvv(mask);
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                if (mask.i32[i] < 0) { // bit 31 set
                    auto err = mem.Read(addr + i * 4, &dst.u32[i], 4);
                    if (err != ErrorCode::Success) return err;
                } else {
                    dst.u32[i] = 0;
                }
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPMASKMOVD (0F38 8E) — Conditional store dwords (masked)
        // Stores to memory only where mask bit 31 is set
        // ================================================================
        if (op == 0x8E) {
            if (!inst.Op(0).IsMemory()) return ErrorCode::InvalidOperandSize;
            YMMValue mask{}, src{};
            ReadVvvv(mask);
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (is256)
                m_state.GetYMM(srcIdx, src.u8);
            else
                std::memcpy(src.u8, m_state.XMM(srcIdx).u8, 16);
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            for (uint32_t i = 0; i < vecLen / 4; ++i) {
                if (mask.i32[i] < 0) { // bit 31 set
                    auto err = mem.Write(addr + i * 4, &src.u32[i], 4);
                    if (err != ErrorCode::Success) return err;
                }
            }
            return ErrorCode::Success;
        }

        // ================================================================
        // VPGATHERDD (0F38 90) — Gather dwords with dword indices
        //
        // Encoding: VPGATHERDD ymm1, [base + ymm_index*scale], ymm_mask
        // Op(0) = destination ymm, Op(1) = VSIB memory operand,
        // vexVVVV = mask register (consumed and zeroed)
        //
        // For each dword lane: if mask bit 31 set, load from
        // base + sign_extend(index[i]) * scale, then clear mask bit.
        // ================================================================
        if (op == 0x90) {
            if (!inst.Op(1).IsMemory()) return ErrorCode::InvalidOperandSize;

            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            YMMValue dst{}, mask{}, indices{};

            // Read current destination and mask
            if (is256) {
                m_state.GetYMM(dstIdx, dst.u8);
                m_state.GetYMM(vvvv, mask.u8);
            } else {
                std::memcpy(dst.u8, m_state.XMM(dstIdx).u8, 16);
                std::memcpy(mask.u8, m_state.XMM(vvvv).u8, 16);
            }

            // Read the index register from the VSIB encoding
            // The index register is encoded in the SIB.index field of Op(1)
            uint8_t idxReg = inst.Op(1).mem.indexReg;
            uint8_t scale  = inst.Op(1).mem.scale;
            if (is256)
                m_state.GetYMM(idxReg, indices.u8);
            else
                std::memcpy(indices.u8, m_state.XMM(idxReg).u8, 16);

            // Base address (without index*scale — that's per-element)
            GuestAddress base = 0;
            if (inst.Op(1).mem.hasBase)
                base = m_state.gpr[inst.Op(1).mem.baseReg & 0x0F];
            base += inst.Op(1).mem.displacement;

            uint32_t elems = vecLen / 4;
            for (uint32_t i = 0; i < elems; ++i) {
                if (mask.i32[i] < 0) { // bit 31 set
                    int64_t offset = static_cast<int64_t>(indices.i32[i]) * scale;
                    GuestAddress elemAddr = base + static_cast<GuestAddress>(offset);
                    auto err = mem.Read(elemAddr, &dst.u32[i], 4);
                    if (err != ErrorCode::Success) return err;
                }
            }

            // Write destination and zero the mask register
            YMMValue zeroMask{};
            if (is256) {
                m_state.SetYMM(dstIdx, dst.u8);
                m_state.SetYMM(vvvv, zeroMask.u8);
            } else {
                std::memcpy(m_state.XMM(dstIdx).u8, dst.u8, 16);
                m_state.ClearYMMHigh(dstIdx);
                m_state.XMM(vvvv).Clear();
                m_state.ClearYMMHigh(vvvv);
            }
            return ErrorCode::Success;
        }

    } // end vexMap==2 && vexPP==1

    // ====================================================================
    // MAP 0F3A (vexMMMMM=3)
    // ====================================================================
    if (vexMap == 3 && vexPP == 1) {

        // ================================================================
        // VPERMQ (0F3A 00) — Permute qwords (imm8 control)
        // Only valid for vexL=1, W=1
        // ================================================================
        if (op == 0x00) {
            if (!is256) return ErrorCode::UnimplementedOpcode;
            YMMValue src{}, dst{};
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
            dst.u64[0] = src.u64[(imm >> 0) & 3];
            dst.u64[1] = src.u64[(imm >> 2) & 3];
            dst.u64[2] = src.u64[(imm >> 4) & 3];
            dst.u64[3] = src.u64[(imm >> 6) & 3];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPERMPD (0F3A 01) — Permute double-precision FP (imm8 control)
        // Same encoding as VPERMQ but for doubles
        // ================================================================
        if (op == 0x01) {
            if (!is256) return ErrorCode::UnimplementedOpcode;
            YMMValue src{}, dst{};
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
            dst.u64[0] = src.u64[(imm >> 0) & 3];
            dst.u64[1] = src.u64[(imm >> 2) & 3];
            dst.u64[2] = src.u64[(imm >> 4) & 3];
            dst.u64[3] = src.u64[(imm >> 6) & 3];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPBLENDD (0F3A 02) — Blend dwords by imm8 mask
        // ================================================================
        if (op == 0x02) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
            for (uint32_t i = 0; i < vecLen / 4; ++i)
                dst.u32[i] = (imm & (1u << i)) ? src2.u32[i] : src1.u32[i];
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPERM2I128 (0F3A 06) — Permute 128-bit integer lanes
        // Only valid for vexL=1
        // imm8[3:0] selects source for low lane, imm8[7:4] for high lane
        //   [1:0] / [5:4]: 0=src1 low, 1=src1 high, 2=src2 low, 3=src2 high
        //   bit 3/7: if set, zero that lane
        // ================================================================
        if (op == 0x06) {
            if (!is256) return ErrorCode::UnimplementedOpcode;
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);

            // Pointers to 4 possible 128-bit lanes
            const uint8_t* lanes[4] = {
                src1.u8,      // src1 low  (0)
                src1.u8 + 16, // src1 high (1)
                src2.u8,      // src2 low  (2)
                src2.u8 + 16  // src2 high (3)
            };

            // Low 128-bit lane of destination
            if (imm & 0x08) {
                std::memset(dst.u8, 0, 16);
            } else {
                std::memcpy(dst.u8, lanes[imm & 0x03], 16);
            }

            // High 128-bit lane of destination
            if (imm & 0x80) {
                std::memset(dst.u8 + 16, 0, 16);
            } else {
                std::memcpy(dst.u8 + 16, lanes[(imm >> 4) & 0x03], 16);
            }

            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VPBLENDW (0F3A 0E) — Blend words by imm8 mask (per lane)
        // imm8 bit i selects word i within each 128-bit lane
        // ================================================================
        if (op == 0x0E) {
            YMMValue src1{}, src2{}, dst{};
            ReadVvvv(src1);
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;
            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
            uint32_t lanes = vecLen / 16;
            for (uint32_t lane = 0; lane < lanes; ++lane) {
                uint32_t wbase = lane * 8;
                for (uint32_t i = 0; i < 8; ++i)
                    dst.u16[wbase + i] = (imm & (1u << i))
                        ? src2.u16[wbase + i]
                        : src1.u16[wbase + i];
            }
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VINSERTI128 (0F3A 38) — Insert 128-bit into 256-bit
        // imm8[0] selects which 128-bit lane to replace
        // ================================================================
        if (op == 0x38) {
            if (!is256) return ErrorCode::UnimplementedOpcode;
            YMMValue dst{};
            ReadVvvv(dst);
            XMMReg src{};
            if (inst.Op(1).IsRegister()) {
                src = m_state.XMM(inst.Op(1).reg.regIndex);
            } else if (inst.Op(1).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, src.u8, 16);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0x01);
            std::memcpy(dst.u8 + imm * 16, src.u8, 16);
            WriteDst(dst);
            return ErrorCode::Success;
        }

        // ================================================================
        // VEXTRACTI128 (0F3A 39) — Extract 128-bit from 256-bit
        // imm8[0] selects which 128-bit lane to extract
        // Destination is XMM or 128-bit memory
        // ================================================================
        if (op == 0x39) {
            if (!is256) return ErrorCode::UnimplementedOpcode;
            YMMValue src{};
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            m_state.GetYMM(srcIdx, src.u8);
            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0x01);
            const uint8_t* lane = src.u8 + imm * 16;

            if (inst.Op(0).IsRegister()) {
                uint8_t dstIdx = inst.Op(0).reg.regIndex;
                std::memcpy(m_state.XMM(dstIdx).u8, lane, 16);
                m_state.ClearYMMHigh(dstIdx);
            } else if (inst.Op(0).IsMemory()) {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                auto err = mem.Write(addr, lane, 16);
                if (err != ErrorCode::Success) return err;
            } else {
                return ErrorCode::InvalidOperandSize;
            }
            return ErrorCode::Success;
        }

    } // end vexMap==3 && vexPP==1

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
