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

namespace {

[[nodiscard]] bool HasOperands(const DecodedInstruction& inst, uint8_t count) noexcept {
    return inst.operandCount >= count;
}

[[nodiscard]] uint64_t StackMaxValue(OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size16: return 0xFFFFull;
        case OperandSize::Size32: return 0xFFFFFFFFull;
        case OperandSize::Size64: return 0xFFFFFFFFFFFFFFFFull;
        default: return 0;
    }
}

[[nodiscard]] bool IsSupportedStackSize(OperandSize size) noexcept {
    return size == OperandSize::Size16 || size == OperandSize::Size32 || size == OperandSize::Size64;
}

[[nodiscard]] uint64_t GetStackPointer(const CPUState& state, OperandSize size) noexcept {
    return state.GetRegBySize(GPR::RSP, size);
}

void SetStackPointer(CPUState& state, OperandSize size, uint64_t value) noexcept {
    state.SetRegBySize(GPR::RSP, value, size);
}

[[nodiscard]] bool TrySubtractStackPointer(uint64_t value, OperandSize size, uint64_t amount, uint64_t& result) noexcept {
    if (!IsSupportedStackSize(size) || amount > value) return false;
    result = (value - amount) & StackMaxValue(size);
    return true;
}

[[nodiscard]] bool TryAddStackPointer(uint64_t value, OperandSize size, uint64_t amount, uint64_t& result) noexcept {
    const uint64_t maxValue = StackMaxValue(size);
    if (!IsSupportedStackSize(size) || value > maxValue - amount) return false;
    result = (value + amount) & maxValue;
    return true;
}

[[nodiscard]] ErrorCode SafeStackPush(CPUState& state, VirtualMemory& mem, uint64_t value, OperandSize size) noexcept {
    const uint32_t bytes = static_cast<uint32_t>(size);
    uint64_t nextSp = 0;
    if (!TrySubtractStackPointer(GetStackPointer(state, size), size, bytes, nextSp)) {
        return ErrorCode::StackOverflow;
    }

    const auto err = mem.Write(nextSp, &value, bytes);
    if (err != ErrorCode::Success) return err;

    SetStackPointer(state, size, nextSp);
    return ErrorCode::Success;
}

[[nodiscard]] ErrorCode SafeStackPop(CPUState& state, VirtualMemory& mem, uint64_t& value, OperandSize size) noexcept {
    const uint32_t bytes = static_cast<uint32_t>(size);
    const uint64_t currentSp = GetStackPointer(state, size);
    uint64_t nextSp = 0;
    if (!TryAddStackPointer(currentSp, size, bytes, nextSp)) {
        return ErrorCode::StackUnderflow;
    }

    value = 0;
    const auto err = mem.Read(currentSp, &value, bytes);
    if (err != ErrorCode::Success) return err;

    SetStackPointer(state, size, nextSp);
    return ErrorCode::Success;
}

[[nodiscard]] ErrorCode ValidateStackOperand(const DecodedInstruction& inst) noexcept {
    return HasOperands(inst, 1) ? ErrorCode::Success : ErrorCode::InvalidOperandSize;
}

} // namespace

ErrorCode CPU::ExecuteStack(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize pushSize = m_state.Is64Bit() ? OperandSize::Size64 : inst.operandSize;

    if (inst.opcodeMap != OpcodeMap::OneByte) return ErrorCode::UnimplementedOpcode;
    if (!IsSupportedStackSize(pushSize)) return ErrorCode::InvalidOperandSize;

    // === PUSH reg (0x50-0x57) ===
    if (op >= 0x50 && op <= 0x57) {
        uint8_t regIdx = (op - 0x50) | (inst.prefixes.rexB ? 8 : 0);
        uint64_t val = m_state.GetRegBySize(static_cast<GPR>(regIdx), pushSize);
        return SafeStackPush(m_state, mem, val, pushSize);
    }

    // === POP reg (0x58-0x5F) ===
    if (op >= 0x58 && op <= 0x5F) {
        uint8_t regIdx = (op - 0x58) | (inst.prefixes.rexB ? 8 : 0);
        uint64_t val = 0;
        auto err = SafeStackPop(m_state, mem, val, pushSize);
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
        return SafeStackPush(m_state, mem, val, pushSize);
    }

    // === PUSH imm16/32 (0x68) ===
    if (op == 0x68) {
        uint64_t val = static_cast<uint64_t>(inst.immediate);
        if (pushSize == OperandSize::Size64) {
            val = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(inst.immediate)));
        }
        return SafeStackPush(m_state, mem, val, pushSize);
    }

    // === PUSH r/m (0xFF /6) ===
    if (op == 0xFF && inst.opcodeExt == 6) {
        auto validation = ValidateStackOperand(inst);
        if (validation != ErrorCode::Success) return validation;

        uint64_t val = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, val);
        if (err != ErrorCode::Success) return err;
        return SafeStackPush(m_state, mem, val, pushSize);
    }

    // === POP r/m (0x8F /0) ===
    if (op == 0x8F && inst.opcodeExt == 0) {
        auto validation = ValidateStackOperand(inst);
        if (validation != ErrorCode::Success) return validation;

        uint64_t val = 0;
        auto err = SafeStackPop(m_state, mem, val, pushSize);
        if (err != ErrorCode::Success) return err;
        return WriteOperand(inst.Op(0), inst, mem, val);
    }

    // === ENTER (0xC8) — Create stack frame ===
    if (op == 0xC8) {
        uint16_t allocSize = static_cast<uint16_t>(inst.immediate & 0xFFFF);
        uint8_t nestLevel = static_cast<uint8_t>((inst.immediate >> 16) & 0x1F);

        const uint64_t oldFramePointer = m_state.GetRegBySize(GPR::RBP, pushSize);
        auto err = SafeStackPush(m_state, mem, oldFramePointer, pushSize);
        if (err != ErrorCode::Success) return err;

        uint64_t framePtr = GetStackPointer(m_state, pushSize);

        if (nestLevel > 0) {
            uint64_t frameCursor = oldFramePointer;
            for (uint8_t i = 1; i < nestLevel; i++) {
                if (!TrySubtractStackPointer(frameCursor, pushSize, static_cast<uint64_t>(pushSize), frameCursor)) {
                    return ErrorCode::StackUnderflow;
                }
                uint64_t val = 0;
                err = mem.Read(frameCursor, &val, static_cast<uint32_t>(pushSize));
                if (err != ErrorCode::Success) return err;
                err = SafeStackPush(m_state, mem, val, pushSize);
                if (err != ErrorCode::Success) return err;
            }
            err = SafeStackPush(m_state, mem, framePtr, pushSize);
            if (err != ErrorCode::Success) return err;
        }

        m_state.SetRegBySize(GPR::RBP, framePtr, pushSize);
        uint64_t allocatedSp = 0;
        if (!TrySubtractStackPointer(GetStackPointer(m_state, pushSize), pushSize, allocSize, allocatedSp)) {
            return ErrorCode::StackOverflow;
        }
        SetStackPointer(m_state, pushSize, allocatedSp);
        return ErrorCode::Success;
    }

    // === LEAVE (0xC9) — Destroy stack frame ===
    if (op == 0xC9) {
        SetStackPointer(m_state, pushSize, m_state.GetRegBySize(GPR::RBP, pushSize));
        uint64_t val = 0;
        auto err = SafeStackPop(m_state, mem, val, pushSize);
        if (err != ErrorCode::Success) return err;
        m_state.SetRegBySize(GPR::RBP, val, pushSize);
        return ErrorCode::Success;
    }

    // === PUSHAD (0x60) — 32-bit mode only ===
    if (op == 0x60 && !m_state.Is64Bit()) {
        const OperandSize pushaSize = (inst.operandSize == OperandSize::Size16)
            ? OperandSize::Size16
            : OperandSize::Size32;
        uint64_t savedSP = m_state.GetRegBySize(GPR::RSP, pushaSize);
        static constexpr GPR pushOrder[] = {
            GPR::RAX, GPR::RCX, GPR::RDX, GPR::RBX,
            GPR::RSP, GPR::RBP, GPR::RSI, GPR::RDI
        };
        for (int i = 0; i < 8; i++) {
            uint64_t val = (pushOrder[i] == GPR::RSP)
                ? savedSP
                : m_state.GetRegBySize(pushOrder[i], pushaSize);
            auto err = SafeStackPush(m_state, mem, val, pushaSize);
            if (err != ErrorCode::Success) return err;
        }
        return ErrorCode::Success;
    }

    // === POPAD (0x61) — 32-bit mode only ===
    if (op == 0x61 && !m_state.Is64Bit()) {
        const OperandSize popaSize = (inst.operandSize == OperandSize::Size16)
            ? OperandSize::Size16
            : OperandSize::Size32;
        static constexpr GPR popOrder[] = {
            GPR::RDI, GPR::RSI, GPR::RBP, GPR::RSP,
            GPR::RBX, GPR::RDX, GPR::RCX, GPR::RAX
        };
        for (int i = 0; i < 8; i++) {
            uint64_t val = 0;
            auto err = SafeStackPop(m_state, mem, val, popaSize);
            if (err != ErrorCode::Success) return err;
            if (popOrder[i] != GPR::RSP) { // Skip RSP restore
                m_state.SetRegBySize(popOrder[i], val, popaSize);
            }
        }
        return ErrorCode::Success;
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
