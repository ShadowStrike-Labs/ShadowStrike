/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SSE2Ops.cpp - SSE/SSE2 operations for x86/x64 emulation
 *               Packed integer arithmetic, compare, logical, shift,
 *               shuffle/unpack, data movement, conversion, scalar arithmetic
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
// Saturation Helpers for Packed Operations
// ============================================================================

namespace {

[[nodiscard]] inline int8_t SatI8(int16_t v) noexcept {
    if (v > 127) return 127;
    if (v < -128) return -128;
    return static_cast<int8_t>(v);
}

[[nodiscard]] inline int16_t SatI16(int32_t v) noexcept {
    if (v > 32767) return 32767;
    if (v < -32768) return -32768;
    return static_cast<int16_t>(v);
}

[[nodiscard]] inline uint8_t SatU8(int16_t v) noexcept {
    if (v > 255) return 255;
    if (v < 0) return 0;
    return static_cast<uint8_t>(v);
}

[[nodiscard]] inline uint16_t SatU16(int32_t v) noexcept {
    if (v > 65535) return 65535;
    if (v < 0) return 0;
    return static_cast<uint16_t>(v);
}

} // anonymous namespace

// ============================================================================
// SSE/SSE2 Instruction Handler
// ============================================================================

ErrorCode CPU::ExecuteSSE2(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (inst.opcodeMap != OpcodeMap::TwoByte) return ErrorCode::UnimplementedOpcode;

    uint8_t op = inst.opcode;
    bool has66 = inst.prefixes.hasOpSizeOverride;
    bool hasF2 = inst.prefixes.hasRepNE;
    bool hasF3 = inst.prefixes.hasRep;

    // Helper: read 128-bit XMM source from Op(1)
    auto ReadSrcXMM = [&](XMMReg& out) -> ErrorCode {
        if (inst.Op(1).IsRegister()) {
            out = m_state.XMM(inst.Op(1).reg.regIndex);
            return ErrorCode::Success;
        }
        if (inst.Op(1).IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            return mem.Read(addr, out.u8, 16);
        }
        return ErrorCode::InvalidOperandSize;
    };

    // ====================================================================
    // XORPS / XORPD (0F 57)
    // ====================================================================
    if (op == 0x57) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex;
        XMMReg& dst = m_state.XMM(dstIdx);
        XMMReg src{};
        auto err = ReadSrcXMM(src);
        if (err != ErrorCode::Success) return err;
        dst.u64[0] ^= src.u64[0];
        dst.u64[1] ^= src.u64[1];
        return ErrorCode::Success;
    }

    // ====================================================================
    // PXOR (66 0F EF)
    // ====================================================================
    if (op == 0xEF && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex;
        XMMReg& dst = m_state.XMM(dstIdx);
        XMMReg src{};
        auto err = ReadSrcXMM(src);
        if (err != ErrorCode::Success) return err;
        dst.u64[0] ^= src.u64[0];
        dst.u64[1] ^= src.u64[1];
        return ErrorCode::Success;
    }

    // ====================================================================
    // MOVAPS (0F 28/29) — aligned, 16-byte
    // ====================================================================
    if (op == 0x28 || op == 0x29) {
        if (op == 0x28) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            if (inst.Op(1).IsRegister()) {
                m_state.XMM(dstIdx) = m_state.XMM(inst.Op(1).reg.regIndex);
            } else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                if (addr & 0xF) return ErrorCode::UnalignedAccess;
                auto err = mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        } else {
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (inst.Op(0).IsRegister()) {
                m_state.XMM(inst.Op(0).reg.regIndex) = m_state.XMM(srcIdx);
            } else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                if (addr & 0xF) return ErrorCode::UnalignedAccess;
                auto err = mem.Write(addr, m_state.XMM(srcIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        }
        return ErrorCode::Success;
    }

    // ====================================================================
    // MOVUPS/MOVUPD/MOVSS/MOVSD (0F 10/11)
    // ====================================================================
    if (op == 0x10 || op == 0x11) {
        if (!has66 && !hasF3 && !hasF2) {
            // MOVUPS
            if (op == 0x10) {
                uint8_t dstIdx = inst.Op(0).reg.regIndex;
                if (inst.Op(1).IsRegister()) m_state.XMM(dstIdx) = m_state.XMM(inst.Op(1).reg.regIndex);
                else {
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                    auto err = mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
                    if (err != ErrorCode::Success) return err;
                }
            } else {
                uint8_t srcIdx = inst.Op(1).reg.regIndex;
                if (inst.Op(0).IsRegister()) m_state.XMM(inst.Op(0).reg.regIndex) = m_state.XMM(srcIdx);
                else {
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    auto err = mem.Write(addr, m_state.XMM(srcIdx).u8, 16);
                    if (err != ErrorCode::Success) return err;
                }
            }
            return ErrorCode::Success;
        }
        if (has66) {
            // MOVUPD — same as MOVUPS
            if (op == 0x10) {
                uint8_t dstIdx = inst.Op(0).reg.regIndex;
                if (inst.Op(1).IsRegister()) m_state.XMM(dstIdx) = m_state.XMM(inst.Op(1).reg.regIndex);
                else {
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                    auto err = mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
                    if (err != ErrorCode::Success) return err;
                }
            } else {
                uint8_t srcIdx = inst.Op(1).reg.regIndex;
                if (inst.Op(0).IsRegister()) m_state.XMM(inst.Op(0).reg.regIndex) = m_state.XMM(srcIdx);
                else {
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    auto err = mem.Write(addr, m_state.XMM(srcIdx).u8, 16);
                    if (err != ErrorCode::Success) return err;
                }
            }
            return ErrorCode::Success;
        }
        if (hasF3 && op == 0x10) { // MOVSS load
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            XMMReg& dst = m_state.XMM(dstIdx);
            if (inst.Op(1).IsRegister()) { dst.f32[0] = m_state.XMM(inst.Op(1).reg.regIndex).f32[0]; }
            else { dst.Clear(); GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, dst.u8, 4); if (e != ErrorCode::Success) return e; }
            return ErrorCode::Success;
        }
        if (hasF3 && op == 0x11) { // MOVSS store
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (inst.Op(0).IsRegister()) m_state.XMM(inst.Op(0).reg.regIndex).f32[0] = m_state.XMM(srcIdx).f32[0];
            else { GuestAddress a = CalculateEffectiveAddress(inst.Op(0), inst); auto e = mem.Write(a, m_state.XMM(srcIdx).u8, 4); if (e != ErrorCode::Success) return e; }
            return ErrorCode::Success;
        }
        if (hasF2 && op == 0x10) { // MOVSD load
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            XMMReg& dst = m_state.XMM(dstIdx);
            if (inst.Op(1).IsRegister()) { dst.f64[0] = m_state.XMM(inst.Op(1).reg.regIndex).f64[0]; }
            else { dst.Clear(); GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, dst.u8, 8); if (e != ErrorCode::Success) return e; }
            return ErrorCode::Success;
        }
        if (hasF2 && op == 0x11) { // MOVSD store
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (inst.Op(0).IsRegister()) m_state.XMM(inst.Op(0).reg.regIndex).f64[0] = m_state.XMM(srcIdx).f64[0];
            else { GuestAddress a = CalculateEffectiveAddress(inst.Op(0), inst); auto e = mem.Write(a, m_state.XMM(srcIdx).u8, 8); if (e != ErrorCode::Success) return e; }
            return ErrorCode::Success;
        }
    }

    // ====================================================================
    // MOVDQA (66 0F 6F/7F) / MOVDQU (F3 0F 6F/7F)
    // ====================================================================
    if ((op == 0x6F || op == 0x7F) && has66) {
        bool isLoad = (op == 0x6F);
        if (isLoad) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            if (inst.Op(1).IsRegister()) m_state.XMM(dstIdx) = m_state.XMM(inst.Op(1).reg.regIndex);
            else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                if (addr & 0xF) return ErrorCode::UnalignedAccess;
                auto err = mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        } else {
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (inst.Op(0).IsRegister()) m_state.XMM(inst.Op(0).reg.regIndex) = m_state.XMM(srcIdx);
            else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                if (addr & 0xF) return ErrorCode::UnalignedAccess;
                auto err = mem.Write(addr, m_state.XMM(srcIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        }
        return ErrorCode::Success;
    }
    if ((op == 0x6F || op == 0x7F) && hasF3) {
        bool isLoad = (op == 0x6F);
        if (isLoad) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            if (inst.Op(1).IsRegister()) m_state.XMM(dstIdx) = m_state.XMM(inst.Op(1).reg.regIndex);
            else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        } else {
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (inst.Op(0).IsRegister()) m_state.XMM(inst.Op(0).reg.regIndex) = m_state.XMM(srcIdx);
            else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                auto err = mem.Write(addr, m_state.XMM(srcIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        }
        return ErrorCode::Success;
    }

    // ====================================================================
    // PACKED INTEGER ARITHMETIC
    // ====================================================================

    // PADDB/PADDW/PADDD (66 0F FC/FD/FE)
    if (op >= 0xFC && op <= 0xFE && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0xFC) { for (int i = 0; i < 16; i++) dst.u8[i] += src.u8[i]; }
        else if (op == 0xFD) { for (int i = 0; i < 8; i++) dst.u16[i] += src.u16[i]; }
        else { for (int i = 0; i < 4; i++) dst.u32[i] += src.u32[i]; }
        return ErrorCode::Success;
    }
    // PADDQ (66 0F D4)
    if (op == 0xD4 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        dst.u64[0] += src.u64[0]; dst.u64[1] += src.u64[1];
        return ErrorCode::Success;
    }
    // PSUBB/PSUBW/PSUBD (66 0F F8/F9/FA)
    if (op >= 0xF8 && op <= 0xFA && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0xF8) { for (int i = 0; i < 16; i++) dst.u8[i] -= src.u8[i]; }
        else if (op == 0xF9) { for (int i = 0; i < 8; i++) dst.u16[i] -= src.u16[i]; }
        else { for (int i = 0; i < 4; i++) dst.u32[i] -= src.u32[i]; }
        return ErrorCode::Success;
    }
    // PSUBQ (66 0F FB)
    if (op == 0xFB && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        dst.u64[0] -= src.u64[0]; dst.u64[1] -= src.u64[1];
        return ErrorCode::Success;
    }
    // PADDSB/PADDSW (66 0F EC/ED)
    if ((op == 0xEC || op == 0xED) && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0xEC) { for (int i = 0; i < 16; i++) dst.i8[i] = SatI8(static_cast<int16_t>(dst.i8[i]) + src.i8[i]); }
        else { for (int i = 0; i < 8; i++) dst.i16[i] = SatI16(static_cast<int32_t>(dst.i16[i]) + src.i16[i]); }
        return ErrorCode::Success;
    }
    // PADDUSB/PADDUSW (66 0F DC/DD)
    if ((op == 0xDC || op == 0xDD) && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0xDC) { for (int i = 0; i < 16; i++) { uint16_t r = static_cast<uint16_t>(dst.u8[i]) + src.u8[i]; dst.u8[i] = (r > 255) ? 255 : static_cast<uint8_t>(r); } }
        else { for (int i = 0; i < 8; i++) { uint32_t r = static_cast<uint32_t>(dst.u16[i]) + src.u16[i]; dst.u16[i] = (r > 65535) ? 65535 : static_cast<uint16_t>(r); } }
        return ErrorCode::Success;
    }
    // PSUBSB/PSUBSW (66 0F E8/E9)
    if ((op == 0xE8 || op == 0xE9) && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0xE8) { for (int i = 0; i < 16; i++) dst.i8[i] = SatI8(static_cast<int16_t>(dst.i8[i]) - src.i8[i]); }
        else { for (int i = 0; i < 8; i++) dst.i16[i] = SatI16(static_cast<int32_t>(dst.i16[i]) - src.i16[i]); }
        return ErrorCode::Success;
    }
    // PSUBUSB/PSUBUSW (66 0F D8/D9)
    if ((op == 0xD8 || op == 0xD9) && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0xD8) { for (int i = 0; i < 16; i++) { int16_t r = static_cast<int16_t>(dst.u8[i]) - src.u8[i]; dst.u8[i] = (r < 0) ? 0 : static_cast<uint8_t>(r); } }
        else { for (int i = 0; i < 8; i++) { int32_t r = static_cast<int32_t>(dst.u16[i]) - src.u16[i]; dst.u16[i] = (r < 0) ? 0 : static_cast<uint16_t>(r); } }
        return ErrorCode::Success;
    }
    // PMULLW (66 0F D5)
    if (op == 0xD5 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 8; i++) dst.u16[i] = static_cast<uint16_t>(static_cast<int32_t>(dst.i16[i]) * src.i16[i]);
        return ErrorCode::Success;
    }
    // PMULHW (66 0F E5)
    if (op == 0xE5 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 8; i++) { int32_t p = static_cast<int32_t>(dst.i16[i]) * src.i16[i]; dst.i16[i] = static_cast<int16_t>(p >> 16); }
        return ErrorCode::Success;
    }
    // PMULHUW (66 0F E4)
    if (op == 0xE4 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 8; i++) { uint32_t p = static_cast<uint32_t>(dst.u16[i]) * src.u16[i]; dst.u16[i] = static_cast<uint16_t>(p >> 16); }
        return ErrorCode::Success;
    }
    // PMULUDQ (66 0F F4)
    if (op == 0xF4 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint64_t lo = static_cast<uint64_t>(dst.u32[0]) * src.u32[0];
        uint64_t hi = static_cast<uint64_t>(dst.u32[2]) * src.u32[2];
        dst.u64[0] = lo; dst.u64[1] = hi;
        return ErrorCode::Success;
    }
    // PMADDWD (66 0F F5)
    if (op == 0xF5 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 4; i++) {
            int32_t a = static_cast<int32_t>(dst.i16[i*2]) * src.i16[i*2];
            int32_t b = static_cast<int32_t>(dst.i16[i*2+1]) * src.i16[i*2+1];
            dst.i32[i] = a + b;
        }
        return ErrorCode::Success;
    }
    // PAVGB (66 0F E0) / PAVGW (66 0F E3)
    if ((op == 0xE0 || op == 0xE3) && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0xE0) { for (int i = 0; i < 16; i++) dst.u8[i] = static_cast<uint8_t>((static_cast<uint16_t>(dst.u8[i]) + src.u8[i] + 1) >> 1); }
        else { for (int i = 0; i < 8; i++) dst.u16[i] = static_cast<uint16_t>((static_cast<uint32_t>(dst.u16[i]) + src.u16[i] + 1) >> 1); }
        return ErrorCode::Success;
    }
    // PSADBW (66 0F F6)
    if (op == 0xF6 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint16_t sLo = 0, sHi = 0;
        for (int i = 0; i < 8; i++) { int d = static_cast<int>(dst.u8[i]) - src.u8[i]; sLo += static_cast<uint16_t>(d < 0 ? -d : d); }
        for (int i = 8; i < 16; i++) { int d = static_cast<int>(dst.u8[i]) - src.u8[i]; sHi += static_cast<uint16_t>(d < 0 ? -d : d); }
        dst.u64[0] = sLo; dst.u64[1] = sHi;
        return ErrorCode::Success;
    }
    // PMINUB (66 0F DA)
    if (op == 0xDA && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 16; i++) dst.u8[i] = std::min(dst.u8[i], src.u8[i]);
        return ErrorCode::Success;
    }
    // PMINSW (66 0F EA)
    if (op == 0xEA && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 8; i++) dst.i16[i] = std::min(dst.i16[i], src.i16[i]);
        return ErrorCode::Success;
    }
    // PMAXUB (66 0F DE)
    if (op == 0xDE && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 16; i++) dst.u8[i] = std::max(dst.u8[i], src.u8[i]);
        return ErrorCode::Success;
    }
    // PMAXSW (66 0F EE)
    if (op == 0xEE && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        for (int i = 0; i < 8; i++) dst.i16[i] = std::max(dst.i16[i], src.i16[i]);
        return ErrorCode::Success;
    }

    // ====================================================================
    // PACKED INTEGER COMPARE
    // ====================================================================
    // PCMPEQB/W/D (66 0F 74/75/76)
    if (op >= 0x74 && op <= 0x76 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0x74) { for (int i = 0; i < 16; i++) dst.u8[i] = (dst.u8[i] == src.u8[i]) ? 0xFF : 0; }
        else if (op == 0x75) { for (int i = 0; i < 8; i++) dst.u16[i] = (dst.u16[i] == src.u16[i]) ? 0xFFFF : 0; }
        else { for (int i = 0; i < 4; i++) dst.u32[i] = (dst.u32[i] == src.u32[i]) ? 0xFFFFFFFF : 0; }
        return ErrorCode::Success;
    }
    // PCMPGTB/W/D (66 0F 64/65/66)
    if (op >= 0x64 && op <= 0x66 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        if (op == 0x64) { for (int i = 0; i < 16; i++) dst.u8[i] = (dst.i8[i] > src.i8[i]) ? 0xFF : 0; }
        else if (op == 0x65) { for (int i = 0; i < 8; i++) dst.u16[i] = (dst.i16[i] > src.i16[i]) ? 0xFFFF : 0; }
        else { for (int i = 0; i < 4; i++) dst.u32[i] = (dst.i32[i] > src.i32[i]) ? 0xFFFFFFFF : 0; }
        return ErrorCode::Success;
    }

    // ====================================================================
    // PACKED INTEGER LOGICAL
    // ====================================================================
    // PAND (66 0F DB)
    if (op == 0xDB && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[0] &= s.u64[0]; d.u64[1] &= s.u64[1]; return ErrorCode::Success; }
    // PANDN (66 0F DF)
    if (op == 0xDF && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[0] = (~d.u64[0]) & s.u64[0]; d.u64[1] = (~d.u64[1]) & s.u64[1]; return ErrorCode::Success; }
    // POR (66 0F EB)
    if (op == 0xEB && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[0] |= s.u64[0]; d.u64[1] |= s.u64[1]; return ErrorCode::Success; }
    // ANDPS/ANDPD (0F 54)
    if (op == 0x54) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[0] &= s.u64[0]; d.u64[1] &= s.u64[1]; return ErrorCode::Success; }
    // ANDNPS/ANDNPD (0F 55)
    if (op == 0x55) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[0] = (~d.u64[0]) & s.u64[0]; d.u64[1] = (~d.u64[1]) & s.u64[1]; return ErrorCode::Success; }
    // ORPS/ORPD (0F 56)
    if (op == 0x56) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[0] |= s.u64[0]; d.u64[1] |= s.u64[1]; return ErrorCode::Success; }

    // ====================================================================
    // PACKED SHIFT — register operand
    // ====================================================================
    // PSLLW/D/Q (66 0F F1/F2/F3)
    if (op >= 0xF1 && op <= 0xF3 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint64_t c = src.u64[0];
        if (op == 0xF1) { if (c > 15) dst.Clear(); else { for (int i = 0; i < 8; i++) dst.u16[i] <<= c; } }
        else if (op == 0xF2) { if (c > 31) dst.Clear(); else { for (int i = 0; i < 4; i++) dst.u32[i] <<= c; } }
        else { if (c > 63) dst.Clear(); else { for (int i = 0; i < 2; i++) dst.u64[i] <<= c; } }
        return ErrorCode::Success;
    }
    // PSRLW/D/Q (66 0F D1/D2/D3)
    if (op >= 0xD1 && op <= 0xD3 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint64_t c = src.u64[0];
        if (op == 0xD1) { if (c > 15) dst.Clear(); else { for (int i = 0; i < 8; i++) dst.u16[i] >>= c; } }
        else if (op == 0xD2) { if (c > 31) dst.Clear(); else { for (int i = 0; i < 4; i++) dst.u32[i] >>= c; } }
        else { if (c > 63) dst.Clear(); else { for (int i = 0; i < 2; i++) dst.u64[i] >>= c; } }
        return ErrorCode::Success;
    }
    // PSRAW/D (66 0F E1/E2)
    if ((op == 0xE1 || op == 0xE2) && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint64_t c = src.u64[0];
        if (op == 0xE1) { if (c > 15) c = 15; for (int i = 0; i < 8; i++) dst.i16[i] >>= c; }
        else { if (c > 31) c = 31; for (int i = 0; i < 4; i++) dst.i32[i] >>= c; }
        return ErrorCode::Success;
    }

    // ====================================================================
    // PACKED SHIFT — immediate forms (group opcodes 71/72/73)
    // ====================================================================
    if (op == 0x71 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx);
        uint8_t c = static_cast<uint8_t>(inst.immediate & 0xFF); uint8_t ext = inst.opcodeExt;
        if (ext == 2) { if (c > 15) { for (int i=0;i<8;i++) dst.u16[i]=0; } else { for (int i=0;i<8;i++) dst.u16[i] >>= c; } }
        else if (ext == 4) { uint8_t s = (c > 15) ? 15 : c; for (int i=0;i<8;i++) dst.i16[i] >>= s; }
        else if (ext == 6) { if (c > 15) { for (int i=0;i<8;i++) dst.u16[i]=0; } else { for (int i=0;i<8;i++) dst.u16[i] <<= c; } }
        else return ErrorCode::UnimplementedOpcode;
        return ErrorCode::Success;
    }
    if (op == 0x72 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx);
        uint8_t c = static_cast<uint8_t>(inst.immediate & 0xFF); uint8_t ext = inst.opcodeExt;
        if (ext == 2) { if (c > 31) { for (int i=0;i<4;i++) dst.u32[i]=0; } else { for (int i=0;i<4;i++) dst.u32[i] >>= c; } }
        else if (ext == 4) { uint8_t s = (c > 31) ? 31 : c; for (int i=0;i<4;i++) dst.i32[i] >>= s; }
        else if (ext == 6) { if (c > 31) { for (int i=0;i<4;i++) dst.u32[i]=0; } else { for (int i=0;i<4;i++) dst.u32[i] <<= c; } }
        else return ErrorCode::UnimplementedOpcode;
        return ErrorCode::Success;
    }
    if (op == 0x73 && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx);
        uint8_t c = static_cast<uint8_t>(inst.immediate & 0xFF); uint8_t ext = inst.opcodeExt;
        if (ext == 2) { if (c > 63) dst.Clear(); else { dst.u64[0] >>= c; dst.u64[1] >>= c; } }
        else if (ext == 6) { if (c > 63) dst.Clear(); else { dst.u64[0] <<= c; dst.u64[1] <<= c; } }
        else if (ext == 3) { uint8_t n = (c > 16) ? 16 : c; XMMReg t{}; for (int i=0;i<16-n;i++) t.u8[i]=dst.u8[i+n]; dst=t; }
        else if (ext == 7) { uint8_t n = (c > 16) ? 16 : c; XMMReg t{}; for (int i=n;i<16;i++) t.u8[i]=dst.u8[i-n]; dst=t; }
        else return ErrorCode::UnimplementedOpcode;
        return ErrorCode::Success;
    }

    // ====================================================================
    // SHUFFLE / UNPACK / PACK
    // ====================================================================
    // PSHUFD (66 0F 70)
    if (op == 0x70 && has66 && !hasF2 && !hasF3) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF); XMMReg r{};
        r.u32[0]=src.u32[(imm>>0)&3]; r.u32[1]=src.u32[(imm>>2)&3]; r.u32[2]=src.u32[(imm>>4)&3]; r.u32[3]=src.u32[(imm>>6)&3];
        dst = r; return ErrorCode::Success;
    }
    // PSHUFHW (F3 0F 70)
    if (op == 0x70 && hasF3) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
        dst.u64[0] = src.u64[0];
        dst.u16[4]=src.u16[4+((imm>>0)&3)]; dst.u16[5]=src.u16[4+((imm>>2)&3)]; dst.u16[6]=src.u16[4+((imm>>4)&3)]; dst.u16[7]=src.u16[4+((imm>>6)&3)];
        return ErrorCode::Success;
    }
    // PSHUFLW (F2 0F 70)
    if (op == 0x70 && hasF2) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); XMMReg src{}; auto err = ReadSrcXMM(src); if (err != ErrorCode::Success) return err;
        uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
        dst.u16[0]=src.u16[(imm>>0)&3]; dst.u16[1]=src.u16[(imm>>2)&3]; dst.u16[2]=src.u16[(imm>>4)&3]; dst.u16[3]=src.u16[(imm>>6)&3];
        dst.u64[1] = src.u64[1];
        return ErrorCode::Success;
    }
    // PUNPCKLBW (66 0F 60)
    if (op == 0x60 && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t = d; for (int i=0;i<8;i++){d.u8[i*2]=t.u8[i];d.u8[i*2+1]=s.u8[i];} return ErrorCode::Success; }
    // PUNPCKLWD (66 0F 61)
    if (op == 0x61 && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t = d; for (int i=0;i<4;i++){d.u16[i*2]=t.u16[i];d.u16[i*2+1]=s.u16[i];} return ErrorCode::Success; }
    // PUNPCKLDQ (66 0F 62)
    if (op == 0x62 && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t = d; d.u32[0]=t.u32[0]; d.u32[1]=s.u32[0]; d.u32[2]=t.u32[1]; d.u32[3]=s.u32[1]; return ErrorCode::Success; }
    // PUNPCKLQDQ (66 0F 6C)
    if (op == 0x6C && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[1] = s.u64[0]; return ErrorCode::Success; }
    // PUNPCKHBW (66 0F 68)
    if (op == 0x68 && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t = d; for (int i=0;i<8;i++){d.u8[i*2]=t.u8[i+8];d.u8[i*2+1]=s.u8[i+8];} return ErrorCode::Success; }
    // PUNPCKHWD (66 0F 69)
    if (op == 0x69 && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t = d; for (int i=0;i<4;i++){d.u16[i*2]=t.u16[i+4];d.u16[i*2+1]=s.u16[i+4];} return ErrorCode::Success; }
    // PUNPCKHDQ (66 0F 6A)
    if (op == 0x6A && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t = d; d.u32[0]=t.u32[2]; d.u32[1]=s.u32[2]; d.u32[2]=t.u32[3]; d.u32[3]=s.u32[3]; return ErrorCode::Success; }
    // PUNPCKHQDQ (66 0F 6D)
    if (op == 0x6D && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; d.u64[0]=d.u64[1]; d.u64[1]=s.u64[1]; return ErrorCode::Success; }
    // PACKSSWB (66 0F 63)
    if (op == 0x63 && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t=d; for(int i=0;i<8;i++) d.i8[i]=SatI8(t.i16[i]); for(int i=0;i<8;i++) d.i8[i+8]=SatI8(s.i16[i]); return ErrorCode::Success; }
    // PACKSSDW (66 0F 6B)
    if (op == 0x6B && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t=d; for(int i=0;i<4;i++) d.i16[i]=SatI16(t.i32[i]); for(int i=0;i<4;i++) d.i16[i+4]=SatI16(s.i32[i]); return ErrorCode::Success; }
    // PACKUSWB (66 0F 67)
    if (op == 0x67 && has66) { uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di); XMMReg s{}; auto e = ReadSrcXMM(s); if (e != ErrorCode::Success) return e; XMMReg t=d; for(int i=0;i<8;i++) d.u8[i]=SatU8(t.i16[i]); for(int i=0;i<8;i++) d.u8[i+8]=SatU8(s.i16[i]); return ErrorCode::Success; }

    // ====================================================================
    // DATA MOVEMENT
    // ====================================================================
    // MOVD/MOVQ xmm, r/m32 (66 0F 6E) — with REX.W: MOVQ xmm, r/m64
    if (op == 0x6E && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex; XMMReg& dst = m_state.XMM(dstIdx); dst.Clear();
        uint64_t val = 0; auto err = ReadOperand(inst.Op(1), inst, mem, val); if (err != ErrorCode::Success) return err;
        if (inst.prefixes.rexW) dst.u64[0] = val; else dst.u32[0] = static_cast<uint32_t>(val);
        return ErrorCode::Success;
    }
    // MOVD/MOVQ r/m32, xmm (66 0F 7E) / MOVQ xmm,xmm/m64 (F3 0F 7E)
    if (op == 0x7E) {
        if (has66) {
            uint8_t si = inst.Op(1).reg.regIndex; const XMMReg& s = m_state.XMM(si);
            uint64_t v = inst.prefixes.rexW ? s.u64[0] : static_cast<uint64_t>(s.u32[0]);
            return WriteOperand(inst.Op(0), inst, mem, v);
        }
        if (hasF3) {
            uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
            if (inst.Op(1).IsRegister()) d.u64[0] = m_state.XMM(inst.Op(1).reg.regIndex).u64[0];
            else { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &d.u64[0], 8); if (e != ErrorCode::Success) return e; }
            d.u64[1] = 0;
            return ErrorCode::Success;
        }
    }
    // MOVLPD/MOVLPS load (0F 12)
    if (op == 0x12) {
        uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
        if (inst.Op(1).IsMemory()) { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &d.u64[0], 8); if (e != ErrorCode::Success) return e; return ErrorCode::Success; }
        if (inst.Op(1).IsRegister() && !has66) { d.u64[0] = m_state.XMM(inst.Op(1).reg.regIndex).u64[1]; return ErrorCode::Success; }
        return ErrorCode::UnimplementedOpcode;
    }
    // MOVLPD/MOVLPS store (0F 13)
    if (op == 0x13 && inst.Op(0).IsMemory()) { uint8_t si = inst.Op(1).reg.regIndex; GuestAddress a = CalculateEffectiveAddress(inst.Op(0), inst); return mem.Write(a, &m_state.XMM(si).u64[0], 8); }
    // MOVHPD/MOVHPS load (0F 16)
    if (op == 0x16) {
        uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
        if (inst.Op(1).IsMemory()) { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &d.u64[1], 8); if (e != ErrorCode::Success) return e; return ErrorCode::Success; }
        if (inst.Op(1).IsRegister() && !has66) { d.u64[1] = m_state.XMM(inst.Op(1).reg.regIndex).u64[0]; return ErrorCode::Success; }
        return ErrorCode::UnimplementedOpcode;
    }
    // MOVHPD/MOVHPS store (0F 17)
    if (op == 0x17 && inst.Op(0).IsMemory()) { uint8_t si = inst.Op(1).reg.regIndex; GuestAddress a = CalculateEffectiveAddress(inst.Op(0), inst); return mem.Write(a, &m_state.XMM(si).u64[1], 8); }
    // PMOVMSKB (66 0F D7)
    if (op == 0xD7 && has66) {
        uint8_t si = inst.Op(1).reg.regIndex; const XMMReg& s = m_state.XMM(si);
        uint32_t mask = 0; for (int i = 0; i < 16; i++) { if (s.u8[i] & 0x80) mask |= (1u << i); }
        m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), mask);
        return ErrorCode::Success;
    }
    // MOVMSKPS/MOVMSKPD (0F 50)
    if (op == 0x50) {
        uint8_t si = inst.Op(1).reg.regIndex; const XMMReg& s = m_state.XMM(si); uint32_t mask = 0;
        if (has66) { if (s.u64[0] & (1ULL<<63)) mask|=1; if (s.u64[1] & (1ULL<<63)) mask|=2; }
        else { for (int i=0;i<4;i++) if (s.u32[i] & (1u<<31)) mask|=(1u<<i); }
        m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), mask);
        return ErrorCode::Success;
    }
    // PINSRW (66 0F C4)
    if (op == 0xC4 && has66) {
        uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
        uint64_t v = 0; auto e = ReadOperand(inst.Op(1), inst, mem, v); if (e != ErrorCode::Success) return e;
        d.u16[static_cast<uint8_t>(inst.immediate) & 7] = static_cast<uint16_t>(v);
        return ErrorCode::Success;
    }
    // PEXTRW (66 0F C5)
    if (op == 0xC5 && has66) {
        uint8_t si = inst.Op(1).reg.regIndex; const XMMReg& s = m_state.XMM(si);
        m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint32_t>(s.u16[static_cast<uint8_t>(inst.immediate) & 7]));
        return ErrorCode::Success;
    }
    // MOVNTDQ (66 0F E7) / MOVNTPS (0F 2B) / MOVNTPD (66 0F 2B) — non-temporal stores
    if ((op == 0xE7 && has66) || op == 0x2B) {
        if (inst.Op(0).IsMemory()) {
            uint8_t si = inst.Op(1).reg.regIndex;
            GuestAddress a = CalculateEffectiveAddress(inst.Op(0), inst);
            if (a & 0xF) return ErrorCode::UnalignedAccess;
            return mem.Write(a, m_state.XMM(si).u8, 16);
        }
    }

    // ====================================================================
    // CONVERSION
    // ====================================================================
    // CVTSI2SD (F2 0F 2A)
    if (op == 0x2A && hasF2) {
        uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
        uint64_t v = 0; auto e = ReadOperand(inst.Op(1), inst, mem, v); if (e != ErrorCode::Success) return e;
        d.f64[0] = inst.prefixes.rexW ? static_cast<double>(static_cast<int64_t>(v)) : static_cast<double>(static_cast<int32_t>(v));
        return ErrorCode::Success;
    }
    // CVTSI2SS (F3 0F 2A)
    if (op == 0x2A && hasF3) {
        uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
        uint64_t v = 0; auto e = ReadOperand(inst.Op(1), inst, mem, v); if (e != ErrorCode::Success) return e;
        d.f32[0] = inst.prefixes.rexW ? static_cast<float>(static_cast<int64_t>(v)) : static_cast<float>(static_cast<int32_t>(v));
        return ErrorCode::Success;
    }
    // CVTSD2SI (F2 0F 2D)
    if (op == 0x2D && hasF2) {
        double v = 0;
        if (inst.Op(1).IsRegister()) v = m_state.XMM(inst.Op(1).reg.regIndex).f64[0];
        else { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &v, 8); if (e != ErrorCode::Success) return e; }
        if (inst.prefixes.rexW) m_state.SetReg64(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint64_t>(static_cast<int64_t>(std::llrint(v))));
        else m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint32_t>(static_cast<int32_t>(std::lrint(v))));
        return ErrorCode::Success;
    }
    // CVTSS2SI (F3 0F 2D)
    if (op == 0x2D && hasF3) {
        float v = 0;
        if (inst.Op(1).IsRegister()) v = m_state.XMM(inst.Op(1).reg.regIndex).f32[0];
        else { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &v, 4); if (e != ErrorCode::Success) return e; }
        if (inst.prefixes.rexW) m_state.SetReg64(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint64_t>(static_cast<int64_t>(std::llrintf(v))));
        else m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint32_t>(static_cast<int32_t>(std::lrintf(v))));
        return ErrorCode::Success;
    }
    // CVTTSD2SI (F2 0F 2C)
    if (op == 0x2C && hasF2) {
        double v = 0;
        if (inst.Op(1).IsRegister()) v = m_state.XMM(inst.Op(1).reg.regIndex).f64[0];
        else { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &v, 8); if (e != ErrorCode::Success) return e; }
        if (inst.prefixes.rexW) m_state.SetReg64(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint64_t>(static_cast<int64_t>(v)));
        else m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint32_t>(static_cast<int32_t>(v)));
        return ErrorCode::Success;
    }
    // CVTTSS2SI (F3 0F 2C)
    if (op == 0x2C && hasF3) {
        float v = 0;
        if (inst.Op(1).IsRegister()) v = m_state.XMM(inst.Op(1).reg.regIndex).f32[0];
        else { GuestAddress a = CalculateEffectiveAddress(inst.Op(1), inst); auto e = mem.Read(a, &v, 4); if (e != ErrorCode::Success) return e; }
        if (inst.prefixes.rexW) m_state.SetReg64(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint64_t>(static_cast<int64_t>(v)));
        else m_state.SetReg32(static_cast<GPR>(inst.Op(0).reg.regIndex), static_cast<uint32_t>(static_cast<int32_t>(v)));
        return ErrorCode::Success;
    }
    // CVTSD2SS (F2 0F 5A) / CVTSS2SD (F3 0F 5A) / CVTPS2PD / CVTPD2PS
    if (op == 0x5A) {
        uint8_t di = inst.Op(0).reg.regIndex; XMMReg& d = m_state.XMM(di);
        if (hasF2) { double v; if (inst.Op(1).IsRegister()) v=m_state.XMM(inst.Op(1).reg.regIndex).f64[0]; else { GuestAddress a=CalculateEffectiveAddress(inst.Op(1),inst); auto e=mem.Read(a,&v,8); if(e!=ErrorCode::Success) return e; } d.f32[0]=static_cast<float>(v); return ErrorCode::Success; }
        if (hasF3) { float v; if (inst.Op(1).IsRegister()) v=m_state.XMM(inst.Op(1).reg.regIndex).f32[0]; else { GuestAddress a=CalculateEffectiveAddress(inst.Op(1),inst); auto e=mem.Read(a,&v,4); if(e!=ErrorCode::Success) return e; } d.f64[0]=static_cast<double>(v); return ErrorCode::Success; }
        XMMReg s{}; auto err = ReadSrcXMM(s); if (err != ErrorCode::Success) return err;
        if (has66) { float f0=static_cast<float>(s.f64[0]); float f1=static_cast<float>(s.f64[1]); d.Clear(); d.f32[0]=f0; d.f32[1]=f1; }
        else { d.f64[0]=static_cast<double>(s.f32[0]); d.f64[1]=static_cast<double>(s.f32[1]); }
        return ErrorCode::Success;
    }

    // ====================================================================
    // SCALAR / PACKED ARITHMETIC
    // ====================================================================
    // ADD (0F 58)
    if (op == 0x58) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(hasF2) d.f64[0]+=s.f64[0]; else if(hasF3) d.f32[0]+=s.f32[0]; else if(has66){d.f64[0]+=s.f64[0];d.f64[1]+=s.f64[1];} else{for(int i=0;i<4;i++)d.f32[i]+=s.f32[i];} return ErrorCode::Success; }
    // SUB (0F 5C)
    if (op == 0x5C) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(hasF2) d.f64[0]-=s.f64[0]; else if(hasF3) d.f32[0]-=s.f32[0]; else if(has66){d.f64[0]-=s.f64[0];d.f64[1]-=s.f64[1];} else{for(int i=0;i<4;i++)d.f32[i]-=s.f32[i];} return ErrorCode::Success; }
    // MUL (0F 59)
    if (op == 0x59) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(hasF2) d.f64[0]*=s.f64[0]; else if(hasF3) d.f32[0]*=s.f32[0]; else if(has66){d.f64[0]*=s.f64[0];d.f64[1]*=s.f64[1];} else{for(int i=0;i<4;i++)d.f32[i]*=s.f32[i];} return ErrorCode::Success; }
    // DIV (0F 5E)
    if (op == 0x5E) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(hasF2) d.f64[0]/=s.f64[0]; else if(hasF3) d.f32[0]/=s.f32[0]; else if(has66){d.f64[0]/=s.f64[0];d.f64[1]/=s.f64[1];} else{for(int i=0;i<4;i++)d.f32[i]/=s.f32[i];} return ErrorCode::Success; }
    // SQRT (0F 51)
    if (op == 0x51) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(hasF2) d.f64[0]=std::sqrt(s.f64[0]); else if(hasF3) d.f32[0]=std::sqrtf(s.f32[0]); else if(has66){d.f64[0]=std::sqrt(s.f64[0]);d.f64[1]=std::sqrt(s.f64[1]);} else{for(int i=0;i<4;i++)d.f32[i]=std::sqrtf(s.f32[i]);} return ErrorCode::Success; }
    // MIN (0F 5D)
    if (op == 0x5D) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(hasF2){if(s.f64[0]<d.f64[0])d.f64[0]=s.f64[0];} else if(hasF3){if(s.f32[0]<d.f32[0])d.f32[0]=s.f32[0];} else if(has66){for(int i=0;i<2;i++)if(s.f64[i]<d.f64[i])d.f64[i]=s.f64[i];} else{for(int i=0;i<4;i++)if(s.f32[i]<d.f32[i])d.f32[i]=s.f32[i];} return ErrorCode::Success; }
    // MAX (0F 5F)
    if (op == 0x5F) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(hasF2){if(s.f64[0]>d.f64[0])d.f64[0]=s.f64[0];} else if(hasF3){if(s.f32[0]>d.f32[0])d.f32[0]=s.f32[0];} else if(has66){for(int i=0;i<2;i++)if(s.f64[i]>d.f64[i])d.f64[i]=s.f64[i];} else{for(int i=0;i<4;i++)if(s.f32[i]>d.f32[i])d.f32[i]=s.f32[i];} return ErrorCode::Success; }

    // ====================================================================
    // COMPARE (COMISD/UCOMISD/COMISS/UCOMISS)
    // ====================================================================
    if (op == 0x2F || op == 0x2E) {
        double a, b;
        if (has66) {
            a = m_state.XMM(inst.Op(0).reg.regIndex).f64[0];
            if (inst.Op(1).IsRegister()) b = m_state.XMM(inst.Op(1).reg.regIndex).f64[0];
            else { GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst); auto err = mem.Read(addr, &b, 8); if (err != ErrorCode::Success) return err; }
        } else {
            float fa = m_state.XMM(inst.Op(0).reg.regIndex).f32[0]; float fb;
            if (inst.Op(1).IsRegister()) fb = m_state.XMM(inst.Op(1).reg.regIndex).f32[0];
            else { GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst); auto err = mem.Read(addr, &fb, 4); if (err != ErrorCode::Success) return err; }
            a = static_cast<double>(fa); b = static_cast<double>(fb);
        }
        m_state.eflags.Clear(Flags::CF | Flags::ZF | Flags::PF | Flags::OF | Flags::SF | Flags::AF);
        if (std::isnan(a) || std::isnan(b)) m_state.eflags.Set(Flags::CF | Flags::ZF | Flags::PF);
        else if (a < b) m_state.eflags.Set(Flags::CF);
        else if (a == b) m_state.eflags.Set(Flags::ZF);
        return ErrorCode::Success;
    }

    // SHUFPS (0F C6) / SHUFPD (66 0F C6)
    if (op == 0xC6) {
        uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
        if (has66) { XMMReg t=d; d.u64[0]=(imm&1)?t.u64[1]:t.u64[0]; d.u64[1]=(imm&2)?s.u64[1]:s.u64[0]; }
        else { XMMReg t=d; XMMReg r{}; r.u32[0]=t.u32[(imm>>0)&3]; r.u32[1]=t.u32[(imm>>2)&3]; r.u32[2]=s.u32[(imm>>4)&3]; r.u32[3]=s.u32[(imm>>6)&3]; d=r; }
        return ErrorCode::Success;
    }

    // UNPCKLPS/PD (0F 14)
    if (op == 0x14) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(has66){XMMReg t=d;d.u64[0]=t.u64[0];d.u64[1]=s.u64[0];} else{XMMReg t=d;d.u32[0]=t.u32[0];d.u32[1]=s.u32[0];d.u32[2]=t.u32[1];d.u32[3]=s.u32[1];} return ErrorCode::Success; }
    // UNPCKHPS/PD (0F 15)
    if (op == 0x15) { uint8_t di=inst.Op(0).reg.regIndex; XMMReg& d=m_state.XMM(di); XMMReg s{}; auto e=ReadSrcXMM(s); if(e!=ErrorCode::Success) return e;
        if(has66){d.u64[0]=d.u64[1];d.u64[1]=s.u64[1];} else{XMMReg t=d;d.u32[0]=t.u32[2];d.u32[1]=s.u32[2];d.u32[2]=t.u32[3];d.u32[3]=s.u32[3];} return ErrorCode::Success; }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
