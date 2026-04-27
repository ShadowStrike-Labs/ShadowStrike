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

namespace {

[[nodiscard]] bool HasOperands(const DecodedInstruction& inst, uint8_t count) noexcept {
    return inst.operandCount >= count;
}

[[nodiscard]] bool IsValidTestSize(uint8_t opcode, OperandSize size) noexcept {
    switch (opcode) {
        case 0x84:
        case 0xA8:
            return size == OperandSize::Size8;
        case 0x85:
        case 0xA9:
            return size == OperandSize::Size16 ||
                   size == OperandSize::Size32 ||
                   size == OperandSize::Size64;
        default:
            return false;
    }
}

[[nodiscard]] uint64_t MaskLogicResult(uint64_t value, OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  return value & 0xFFu;
        case OperandSize::Size16: return value & 0xFFFFu;
        case OperandSize::Size32: return value & 0xFFFFFFFFull;
        case OperandSize::Size64: return value;
        default: return 0;
    }
}

[[nodiscard]] ErrorCode UpdateTestFlags(EFlags& flags, uint64_t lhs, uint64_t rhs, OperandSize size) noexcept {
    const uint64_t result = MaskLogicResult(lhs & rhs, size);
    switch (size) {
        case OperandSize::Size8:
            flags.UpdateFlagsLogic8(static_cast<uint8_t>(result));
            return ErrorCode::Success;
        case OperandSize::Size16:
            flags.UpdateFlagsLogic16(static_cast<uint16_t>(result));
            return ErrorCode::Success;
        case OperandSize::Size32:
            flags.UpdateFlagsLogic32(static_cast<uint32_t>(result));
            return ErrorCode::Success;
        case OperandSize::Size64:
            flags.UpdateFlagsLogic64(result);
            return ErrorCode::Success;
        default:
            return ErrorCode::InvalidOperandSize;
    }
}

} // namespace

ErrorCode CPU::ExecuteLogic(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte) return ErrorCode::UnimplementedOpcode;

    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    // === TEST r/m, r (0x84 / 0x85) ===
    if (op == 0x84 || op == 0x85) {
        if (!HasOperands(inst, 2) || !IsValidTestSize(op, size)) {
            return ErrorCode::InvalidOperandSize;
        }
        uint64_t a = 0, b = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, a);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(1), inst, mem, b);
        if (err != ErrorCode::Success) return err;

        return UpdateTestFlags(m_state.eflags, a, b, size);
    }

    // === TEST AL/AX/EAX/RAX, imm (0xA8 / 0xA9) ===
    if (op == 0xA8 || op == 0xA9) {
        if (!HasOperands(inst, 2) || !IsValidTestSize(op, size)) {
            return ErrorCode::InvalidOperandSize;
        }
        uint64_t a = m_state.GetRegBySize(GPR::RAX, size);
        uint64_t imm = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, imm);
        if (err != ErrorCode::Success) return err;

        return UpdateTestFlags(m_state.eflags, a, imm, size);
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
