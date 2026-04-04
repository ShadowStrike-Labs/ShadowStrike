/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * StackOps.cpp — PUSH reg, PUSH imm, POP reg, PUSH r/m, POP r/m,
 *                ENTER, LEAVE, PUSHA/PUSHAD, POPA/POPAD
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"

namespace Phantom {

ErrorCode CPU::ExecuteStack(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize pushSize = m_state.Is64Bit() ? OperandSize::Size64 : inst.operandSize;

    if (inst.opcodeMap != OpcodeMap::OneByte) return ErrorCode::UnimplementedOpcode;

    // === PUSH reg (0x50-0x57) ===
    if (op >= 0x50 && op <= 0x57) {
        uint8_t regIdx = (op - 0x50) | (inst.prefixes.rexB ? 8 : 0);
        uint64_t val = m_state.GetRegBySize(static_cast<GPR>(regIdx), pushSize);
        return StackPush(mem, val, pushSize);
    }

    // === POP reg (0x58-0x5F) ===
    if (op >= 0x58 && op <= 0x5F) {
        uint8_t regIdx = (op - 0x58) | (inst.prefixes.rexB ? 8 : 0);
        uint64_t val = 0;
        auto err = StackPop(mem, val, pushSize);
        if (err != ErrorCode::Success) return err;
        m_state.SetRegBySize(static_cast<GPR>(regIdx), val, pushSize);
        return ErrorCode::Success;
    }

    // === PUSH imm8 (0x6A) ===
    if (op == 0x6A) {
        int8_t imm8 = static_cast<int8_t>(inst.immediate & 0xFF);
        uint64_t val;
        if (pushSize == OperandSize::Size64) {
            val = static_cast<uint64_t>(static_cast<int64_t>(imm8));
        } else if (pushSize == OperandSize::Size32) {
            val = static_cast<uint64_t>(static_cast<uint32_t>(static_cast<int32_t>(imm8)));
        } else {
            val = static_cast<uint64_t>(static_cast<uint16_t>(static_cast<int16_t>(imm8)));
        }
        return StackPush(mem, val, pushSize);
    }

    // === PUSH imm16/32 (0x68) ===
    if (op == 0x68) {
        uint64_t val = static_cast<uint64_t>(inst.immediate);
        if (pushSize == OperandSize::Size64) {
            val = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(inst.immediate)));
        }
        return StackPush(mem, val, pushSize);
    }

    // === PUSH r/m (0xFF /6) ===
    if (op == 0xFF && inst.opcodeExt == 6) {
        uint64_t val = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, val);
        if (err != ErrorCode::Success) return err;
        return StackPush(mem, val, pushSize);
    }

    // === ENTER (0xC8) — Create stack frame ===
    if (op == 0xC8) {
        uint16_t allocSize = static_cast<uint16_t>(inst.immediate & 0xFFFF);
        uint8_t nestLevel = static_cast<uint8_t>((inst.immediate >> 16) & 0x1F);

        auto err = StackPush(mem, m_state.GetRegBySize(GPR::RBP, pushSize), pushSize);
        if (err != ErrorCode::Success) return err;

        uint64_t framePtr = m_state.RSP();

        if (nestLevel > 0) {
            for (uint8_t i = 1; i < nestLevel; i++) {
                uint64_t bpOff = static_cast<uint64_t>(pushSize);
                m_state.SetRegBySize(GPR::RBP,
                    m_state.GetRegBySize(GPR::RBP, pushSize) - bpOff, pushSize);
                uint64_t val = 0;
                err = mem.Read(m_state.GetRegBySize(GPR::RBP, pushSize), &val,
                               static_cast<uint32_t>(pushSize));
                if (err != ErrorCode::Success) return err;
                err = StackPush(mem, val, pushSize);
                if (err != ErrorCode::Success) return err;
            }
            err = StackPush(mem, framePtr, pushSize);
            if (err != ErrorCode::Success) return err;
        }

        m_state.SetRegBySize(GPR::RBP, framePtr, pushSize);
        m_state.SetReg64(GPR::RSP, m_state.RSP() - allocSize);
        return ErrorCode::Success;
    }

    // === LEAVE (0xC9) — Destroy stack frame ===
    if (op == 0xC9) {
        m_state.SetReg64(GPR::RSP, m_state.GetRegBySize(GPR::RBP, pushSize));
        uint64_t val = 0;
        auto err = StackPop(mem, val, pushSize);
        if (err != ErrorCode::Success) return err;
        m_state.SetRegBySize(GPR::RBP, val, pushSize);
        return ErrorCode::Success;
    }

    // === PUSHAD (0x60) — 32-bit mode only ===
    if (op == 0x60 && !m_state.Is64Bit()) {
        uint32_t savedESP = m_state.GetReg32(GPR::RSP);
        static constexpr GPR pushOrder[] = {
            GPR::RAX, GPR::RCX, GPR::RDX, GPR::RBX,
            GPR::RSP, GPR::RBP, GPR::RSI, GPR::RDI
        };
        for (int i = 0; i < 8; i++) {
            uint32_t val = (pushOrder[i] == GPR::RSP) ? savedESP : m_state.GetReg32(pushOrder[i]);
            auto err = StackPush(mem, val, OperandSize::Size32);
            if (err != ErrorCode::Success) return err;
        }
        return ErrorCode::Success;
    }

    // === POPAD (0x61) — 32-bit mode only ===
    if (op == 0x61 && !m_state.Is64Bit()) {
        static constexpr GPR popOrder[] = {
            GPR::RDI, GPR::RSI, GPR::RBP, GPR::RSP,
            GPR::RBX, GPR::RDX, GPR::RCX, GPR::RAX
        };
        for (int i = 0; i < 8; i++) {
            uint64_t val = 0;
            auto err = StackPop(mem, val, OperandSize::Size32);
            if (err != ErrorCode::Success) return err;
            if (popOrder[i] != GPR::RSP) { // Skip RSP restore
                m_state.SetReg32(popOrder[i], static_cast<uint32_t>(val));
            }
        }
        return ErrorCode::Success;
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
