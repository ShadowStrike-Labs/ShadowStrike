/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * LogicOps.cpp — AND, OR, XOR, NOT, TEST
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"

namespace Phantom {

ErrorCode CPU::ExecuteLogic(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    // === TEST r/m, r (0x84 / 0x85) ===
    if (op == 0x84 || op == 0x85) {
        uint64_t a = 0, b = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, a);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(1), inst, mem, b);
        if (err != ErrorCode::Success) return err;

        uint64_t result = a & b;

        switch (size) {
            case OperandSize::Size8:  m_state.eflags.UpdateFlagsLogic8(static_cast<uint8_t>(result)); break;
            case OperandSize::Size16: m_state.eflags.UpdateFlagsLogic16(static_cast<uint16_t>(result)); break;
            case OperandSize::Size32: m_state.eflags.UpdateFlagsLogic32(static_cast<uint32_t>(result)); break;
            case OperandSize::Size64: m_state.eflags.UpdateFlagsLogic64(result); break;
        }
        return ErrorCode::Success;
    }

    // === TEST AL/AX/EAX/RAX, imm (0xA8 / 0xA9) ===
    if (op == 0xA8 || op == 0xA9) {
        uint64_t a = m_state.GetRegBySize(GPR::RAX, size);
        uint64_t imm = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, imm);
        if (err != ErrorCode::Success) return err;

        uint64_t result = a & imm;

        switch (size) {
            case OperandSize::Size8:  m_state.eflags.UpdateFlagsLogic8(static_cast<uint8_t>(result)); break;
            case OperandSize::Size16: m_state.eflags.UpdateFlagsLogic16(static_cast<uint16_t>(result)); break;
            case OperandSize::Size32: m_state.eflags.UpdateFlagsLogic32(static_cast<uint32_t>(result)); break;
            case OperandSize::Size64: m_state.eflags.UpdateFlagsLogic64(result); break;
        }
        return ErrorCode::Success;
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
