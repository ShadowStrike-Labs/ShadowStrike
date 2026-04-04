/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SSE2Ops.cpp — Basic SSE2 operations used by malware
 *               MOVDQA, MOVDQU, MOVAPS, MOVUPS, PXOR, XORPS, XORPD
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include <cstring>

namespace Phantom {

ErrorCode CPU::ExecuteSSE2(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    // SSE2 instructions typically use 0F-prefixed two-byte opcodes
    // with 66/F2/F3 mandatory prefixes to distinguish variants

    if (inst.opcodeMap != OpcodeMap::TwoByte) return ErrorCode::UnimplementedOpcode;

    uint8_t op = inst.opcode;
    bool has66 = inst.prefixes.hasOpSizeOverride;

    // === XORPS xmm, xmm/m128 (0F 57) — No prefix ===
    // === XORPD xmm, xmm/m128 (66 0F 57) — With 66 prefix ===
    if (op == 0x57) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex;
        XMMReg& dst = m_state.XMM(dstIdx);

        if (inst.Op(1).IsRegister()) {
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            const XMMReg& src = m_state.XMM(srcIdx);
            dst.u64[0] ^= src.u64[0];
            dst.u64[1] ^= src.u64[1];
        } else if (inst.Op(1).IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            XMMReg src{};
            auto err = mem.Read(addr, src.u8, 16);
            if (err != ErrorCode::Success) return err;
            dst.u64[0] ^= src.u64[0];
            dst.u64[1] ^= src.u64[1];
        }
        return ErrorCode::Success;
    }

    // === PXOR xmm, xmm/m128 (66 0F EF) ===
    if (op == 0xEF && has66) {
        uint8_t dstIdx = inst.Op(0).reg.regIndex;
        XMMReg& dst = m_state.XMM(dstIdx);

        if (inst.Op(1).IsRegister()) {
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            const XMMReg& src = m_state.XMM(srcIdx);
            dst.u64[0] ^= src.u64[0];
            dst.u64[1] ^= src.u64[1];
        } else if (inst.Op(1).IsMemory()) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            XMMReg src{};
            auto err = mem.Read(addr, src.u8, 16);
            if (err != ErrorCode::Success) return err;
            dst.u64[0] ^= src.u64[0];
            dst.u64[1] ^= src.u64[1];
        }
        return ErrorCode::Success;
    }

    // === MOVAPS xmm, xmm/m128 (0F 28) ===
    // === MOVAPS xmm, xmm/m128 (0F 28) — requires 16-byte alignment ===
    // === MOVAPS xmm/m128, xmm (0F 29) — requires 16-byte alignment ===
    if (op == 0x28 || op == 0x29) {
        if (op == 0x28) {
            // xmm ← xmm/m128
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
            // xmm/m128 ← xmm
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

    // === MOVUPS xmm, xmm/m128 (0F 10) ===
    // === MOVUPS xmm/m128, xmm (0F 11) ===
    if ((op == 0x10 || op == 0x11) && !has66 && !inst.prefixes.hasRep && !inst.prefixes.hasRepNE) {
        if (op == 0x10) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            if (inst.Op(1).IsRegister()) {
                m_state.XMM(dstIdx) = m_state.XMM(inst.Op(1).reg.regIndex);
            } else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        } else {
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (inst.Op(0).IsRegister()) {
                m_state.XMM(inst.Op(0).reg.regIndex) = m_state.XMM(srcIdx);
            } else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                auto err = mem.Write(addr, m_state.XMM(srcIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        }
        return ErrorCode::Success;
    }

    // === MOVDQA xmm, xmm/m128 (66 0F 6F) — requires 16-byte alignment ===
    // === MOVDQA xmm/m128, xmm (66 0F 7F) — requires 16-byte alignment ===
    if ((op == 0x6F || op == 0x7F) && has66) {
        if (op == 0x6F) {
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

    // === MOVDQU xmm, xmm/m128 (F3 0F 6F) ===
    // === MOVDQU xmm/m128, xmm (F3 0F 7F) ===
    if ((op == 0x6F || op == 0x7F) && inst.prefixes.hasRep) {
        if (op == 0x6F) {
            uint8_t dstIdx = inst.Op(0).reg.regIndex;
            if (inst.Op(1).IsRegister()) {
                m_state.XMM(dstIdx) = m_state.XMM(inst.Op(1).reg.regIndex);
            } else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
                auto err = mem.Read(addr, m_state.XMM(dstIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        } else {
            uint8_t srcIdx = inst.Op(1).reg.regIndex;
            if (inst.Op(0).IsRegister()) {
                m_state.XMM(inst.Op(0).reg.regIndex) = m_state.XMM(srcIdx);
            } else {
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                auto err = mem.Write(addr, m_state.XMM(srcIdx).u8, 16);
                if (err != ErrorCode::Success) return err;
            }
        }
        return ErrorCode::Success;
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
