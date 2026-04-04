/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * BitManip.cpp — BT, BTS, BTR, BTC, BSF, BSR, POPCNT, LZCNT, TZCNT
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "../../../Common/Platform.hpp"
#include <bit>

namespace Phantom {

ErrorCode CPU::ExecuteBitManip(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    if (inst.opcodeMap != OpcodeMap::TwoByte) return ErrorCode::UnimplementedOpcode;

    // === BSF (0F BC) — Bit Scan Forward ===
    if (op == 0xBC && !inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        src = MaskToSize(src, size);
        if (src == 0) {
            m_state.eflags.SetZF(true);
            // Destination is undefined; we leave it unchanged
            return ErrorCode::Success;
        }

        m_state.eflags.SetZF(false);
        uint32_t idx = 0;
        switch (size) {
            case OperandSize::Size16: idx = static_cast<uint32_t>(std::countr_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: idx = static_cast<uint32_t>(std::countr_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: idx = static_cast<uint32_t>(std::countr_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }
        return WriteOperand(inst.Op(0), inst, mem, idx);
    }

    // === TZCNT (F3 0F BC) — Trailing Zero Count ===
    if (op == 0xBC && inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        src = MaskToSize(src, size);
        uint32_t cnt = 0;
        switch (size) {
            case OperandSize::Size16: cnt = static_cast<uint32_t>(std::countr_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: cnt = static_cast<uint32_t>(std::countr_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: cnt = static_cast<uint32_t>(std::countr_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }

        m_state.eflags.SetCF(src == 0);
        m_state.eflags.SetZF(cnt == 0);
        return WriteOperand(inst.Op(0), inst, mem, cnt);
    }

    // === BSR (0F BD) — Bit Scan Reverse ===
    if (op == 0xBD && !inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        src = MaskToSize(src, size);
        if (src == 0) {
            m_state.eflags.SetZF(true);
            return ErrorCode::Success;
        }

        m_state.eflags.SetZF(false);
        uint32_t bits = static_cast<uint32_t>(size) * 8;
        uint32_t idx = bits - 1 - static_cast<uint32_t>(std::countl_zero(src));
        // Adjust for smaller sizes
        switch (size) {
            case OperandSize::Size16: idx = 15 - static_cast<uint32_t>(std::countl_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: idx = 31 - static_cast<uint32_t>(std::countl_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: idx = 63 - static_cast<uint32_t>(std::countl_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }
        return WriteOperand(inst.Op(0), inst, mem, idx);
    }

    // === LZCNT (F3 0F BD) — Leading Zero Count ===
    if (op == 0xBD && inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        uint32_t cnt = 0;
        switch (size) {
            case OperandSize::Size16: cnt = static_cast<uint32_t>(std::countl_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: cnt = static_cast<uint32_t>(std::countl_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: cnt = static_cast<uint32_t>(std::countl_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }

        m_state.eflags.SetCF(src == 0);
        m_state.eflags.SetZF(cnt == 0);
        return WriteOperand(inst.Op(0), inst, mem, cnt);
    }

    // === POPCNT (F3 0F B8) ===
    if (op == 0xB8 && inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        uint32_t cnt = 0;
        switch (size) {
            case OperandSize::Size16: cnt = static_cast<uint32_t>(std::popcount(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: cnt = static_cast<uint32_t>(std::popcount(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: cnt = static_cast<uint32_t>(std::popcount(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }

        // POPCNT: all flags cleared, ZF = (src == 0)
        m_state.eflags.SetCF(false);
        m_state.eflags.SetOF(false);
        m_state.eflags.SetSF(false);
        m_state.eflags.SetZF(src == 0);
        m_state.eflags.SetAF(false);
        m_state.eflags.SetPF(false);
        return WriteOperand(inst.Op(0), inst, mem, cnt);
    }

    // === BT/BTS/BTR/BTC — register form (0F A3, 0F AB, 0F B3, 0F BB) ===
    // === BT/BTS/BTR/BTC — immediate form (0F BA /4-7) ===

    // Determine operation type
    enum class BTOp { BT, BTS, BTR, BTC };
    BTOp btOp = BTOp::BT;
    bool isBTGroup = false;

    if (op == 0xA3) { btOp = BTOp::BT;  isBTGroup = true; }
    if (op == 0xAB) { btOp = BTOp::BTS; isBTGroup = true; }
    if (op == 0xB3) { btOp = BTOp::BTR; isBTGroup = true; }
    if (op == 0xBB) { btOp = BTOp::BTC; isBTGroup = true; }

    if (op == 0xBA) {
        isBTGroup = true;
        switch (inst.opcodeExt) {
            case 4: btOp = BTOp::BT;  break;
            case 5: btOp = BTOp::BTS; break;
            case 6: btOp = BTOp::BTR; break;
            case 7: btOp = BTOp::BTC; break;
            default: return ErrorCode::UnimplementedOpcode;
        }
    }

    if (isBTGroup) {
        uint64_t val = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, val);
        if (err != ErrorCode::Success) return err;

        uint64_t bitIdx = 0;
        err = ReadOperand(inst.Op(1), inst, mem, bitIdx);
        if (err != ErrorCode::Success) return err;

        uint8_t bits = static_cast<uint8_t>(size) * 8;
        bitIdx &= (bits - 1); // Mask to operand size

        // Set CF = selected bit
        m_state.eflags.SetCF(((val >> bitIdx) & 1) != 0);

        uint64_t mask = 1ULL << bitIdx;
        switch (btOp) {
            case BTOp::BT:  return ErrorCode::Success; // Just test, no modify
            case BTOp::BTS: val |= mask; break;
            case BTOp::BTR: val &= ~mask; break;
            case BTOp::BTC: val ^= mask; break;
        }

        return WriteOperand(inst.Op(0), inst, mem, val);
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
