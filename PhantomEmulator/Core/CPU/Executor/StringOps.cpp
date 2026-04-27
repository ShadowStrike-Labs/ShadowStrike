/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * StringOps.cpp — MOVS, CMPS, SCAS, STOS, LODS with REP/REPE/REPNE prefixes
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"

namespace Phantom {

// Max iterations per REP to avoid infinite loops in emulation
static constexpr uint64_t kMaxRepIterations = 16 * 1024 * 1024; // 16M

namespace {

[[nodiscard]] bool IsStringOpcode(uint8_t op) noexcept {
    return op == 0xA4 || op == 0xA5 || op == 0xA6 || op == 0xA7 ||
           op == 0xAA || op == 0xAB || op == 0xAC || op == 0xAD ||
           op == 0xAE || op == 0xAF;
}

[[nodiscard]] bool IsByteStringOpcode(uint8_t op) noexcept {
    return op == 0xA4 || op == 0xA6 || op == 0xAA || op == 0xAC || op == 0xAE;
}

[[nodiscard]] bool IsSupportedStringSize(OperandSize size) noexcept {
    return size == OperandSize::Size8 ||
           size == OperandSize::Size16 ||
           size == OperandSize::Size32 ||
           size == OperandSize::Size64;
}

[[nodiscard]] uint64_t AddressMask(AddressSize size) noexcept {
    switch (size) {
        case AddressSize::Addr16: return 0xFFFFull;
        case AddressSize::Addr32: return 0xFFFFFFFFull;
        case AddressSize::Addr64: return 0xFFFFFFFFFFFFFFFFull;
        default: return 0;
    }
}

[[nodiscard]] uint64_t AdvanceStringIndex(uint64_t value, AddressSize addressSize, uint32_t bytes, bool decrement) noexcept {
    const uint64_t mask = AddressMask(addressSize);
    return decrement ? ((value - bytes) & mask) : ((value + bytes) & mask);
}

} // namespace

ErrorCode CPU::ExecuteString(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte) return ErrorCode::UnimplementedOpcode;

    uint8_t op = inst.opcode;
    if (!IsStringOpcode(op)) return ErrorCode::UnimplementedOpcode;
    if (inst.prefixes.hasRep && inst.prefixes.hasRepNE) return ErrorCode::InvalidPrefix;

    OperandSize elemSize = inst.operandSize;

    // For string ops with 0xA4/0xA5 the operand size selects byte/word/dword/qword
    // 0xA4/0xAA/0xAC/0xA6/0xAE = byte variants (force Size8)
    if (IsByteStringOpcode(op)) {
        elemSize = OperandSize::Size8;
    }
    if (!IsSupportedStringSize(elemSize)) return ErrorCode::InvalidOperandSize;

    uint32_t byteCount = static_cast<uint32_t>(elemSize);
    const bool decrement = m_state.eflags.DF();

    bool hasRep   = inst.prefixes.hasRep;
    bool hasRepNE = inst.prefixes.hasRepNE;
    bool isRep    = hasRep || hasRepNE;

    // Get counter register width based on address size
    auto GetCount = [&]() -> uint64_t {
        if (inst.addressSize == AddressSize::Addr64) return m_state.GetReg64(GPR::RCX);
        if (inst.addressSize == AddressSize::Addr32) return m_state.GetReg32(GPR::RCX);
        return m_state.GetReg16(GPR::RCX);
    };

    auto SetCount = [&](uint64_t cnt) {
        if (inst.addressSize == AddressSize::Addr64) m_state.SetReg64(GPR::RCX, cnt);
        else if (inst.addressSize == AddressSize::Addr32) m_state.SetReg32(GPR::RCX, static_cast<uint32_t>(cnt));
        else m_state.SetReg16(GPR::RCX, static_cast<uint16_t>(cnt));
    };

    auto GetSI = [&]() -> uint64_t {
        if (inst.addressSize == AddressSize::Addr64) return m_state.GetReg64(GPR::RSI);
        if (inst.addressSize == AddressSize::Addr32) return m_state.GetReg32(GPR::RSI);
        return m_state.GetReg16(GPR::RSI);
    };

    auto SetSI = [&](uint64_t v) {
        if (inst.addressSize == AddressSize::Addr64) m_state.SetReg64(GPR::RSI, v);
        else if (inst.addressSize == AddressSize::Addr32) m_state.SetReg32(GPR::RSI, static_cast<uint32_t>(v));
        else m_state.SetReg16(GPR::RSI, static_cast<uint16_t>(v));
    };

    auto GetDI = [&]() -> uint64_t {
        if (inst.addressSize == AddressSize::Addr64) return m_state.GetReg64(GPR::RDI);
        if (inst.addressSize == AddressSize::Addr32) return m_state.GetReg32(GPR::RDI);
        return m_state.GetReg16(GPR::RDI);
    };

    auto SetDI = [&](uint64_t v) {
        if (inst.addressSize == AddressSize::Addr64) m_state.SetReg64(GPR::RDI, v);
        else if (inst.addressSize == AddressSize::Addr32) m_state.SetReg32(GPR::RDI, static_cast<uint32_t>(v));
        else m_state.SetReg16(GPR::RDI, static_cast<uint16_t>(v));
    };

    // === MOVS (0xA4 byte, 0xA5 word/dword/qword) ===
    if (op == 0xA4 || op == 0xA5) {
        uint64_t iterations = isRep ? GetCount() : 1;
        if (isRep && iterations == 0) return ErrorCode::Success;
        if (iterations > kMaxRepIterations) iterations = kMaxRepIterations;

        for (uint64_t i = 0; i < iterations; i++) {
            uint64_t val = 0;
            auto err = mem.Read(GetSI(), &val, byteCount);
            if (err != ErrorCode::Success) return err;
            err = mem.Write(GetDI(), &val, byteCount);
            if (err != ErrorCode::Success) return err;

            SetSI(AdvanceStringIndex(GetSI(), inst.addressSize, byteCount, decrement));
            SetDI(AdvanceStringIndex(GetDI(), inst.addressSize, byteCount, decrement));
            if (isRep) SetCount(GetCount() - 1);
        }

        return ErrorCode::Success;
    }

    // === STOS (0xAA byte, 0xAB word/dword/qword) ===
    if (op == 0xAA || op == 0xAB) {
        uint64_t val = m_state.GetRegBySize(GPR::RAX, elemSize);
        uint64_t iterations = isRep ? GetCount() : 1;
        if (isRep && iterations == 0) return ErrorCode::Success;
        if (iterations > kMaxRepIterations) iterations = kMaxRepIterations;

        for (uint64_t i = 0; i < iterations; i++) {
            auto err = mem.Write(GetDI(), &val, byteCount);
            if (err != ErrorCode::Success) return err;
            SetDI(AdvanceStringIndex(GetDI(), inst.addressSize, byteCount, decrement));
            if (isRep) SetCount(GetCount() - 1);
        }

        return ErrorCode::Success;
    }

    // === LODS (0xAC byte, 0xAD word/dword/qword) ===
    if (op == 0xAC || op == 0xAD) {
        uint64_t iterations = isRep ? GetCount() : 1;
        if (isRep && iterations == 0) return ErrorCode::Success;
        if (iterations > kMaxRepIterations) iterations = kMaxRepIterations;

        uint64_t val = 0;
        for (uint64_t i = 0; i < iterations; i++) {
            auto err = mem.Read(GetSI(), &val, byteCount);
            if (err != ErrorCode::Success) return err;
            SetSI(AdvanceStringIndex(GetSI(), inst.addressSize, byteCount, decrement));
            if (isRep) SetCount(GetCount() - 1);
        }
        // Only last value is written to AL/AX/EAX/RAX
        m_state.SetRegBySize(GPR::RAX, val, elemSize);

        return ErrorCode::Success;
    }

    // === CMPS (0xA6 byte, 0xA7 word/dword/qword) ===
    if (op == 0xA6 || op == 0xA7) {
        uint64_t iterations = isRep ? GetCount() : 1;
        if (isRep && iterations == 0) return ErrorCode::Success;
        if (iterations > kMaxRepIterations) iterations = kMaxRepIterations;

        for (uint64_t i = 0; i < iterations; i++) {
            uint64_t a = 0, b = 0;
            auto err = mem.Read(GetSI(), &a, byteCount);
            if (err != ErrorCode::Success) return err;
            err = mem.Read(GetDI(), &b, byteCount);
            if (err != ErrorCode::Success) return err;

            uint64_t diff = a - b;
            switch (elemSize) {
                case OperandSize::Size8:
                    m_state.eflags.UpdateFlagsSub8(static_cast<uint8_t>(a), static_cast<uint8_t>(b), static_cast<uint8_t>(diff)); break;
                case OperandSize::Size16:
                    m_state.eflags.UpdateFlagsSub16(static_cast<uint16_t>(a), static_cast<uint16_t>(b), static_cast<uint16_t>(diff)); break;
                case OperandSize::Size32:
                    m_state.eflags.UpdateFlagsSub32(static_cast<uint32_t>(a), static_cast<uint32_t>(b), static_cast<uint32_t>(diff)); break;
                case OperandSize::Size64:
                    m_state.eflags.UpdateFlagsSub64(a, b, diff); break;
            }

            SetSI(AdvanceStringIndex(GetSI(), inst.addressSize, byteCount, decrement));
            SetDI(AdvanceStringIndex(GetDI(), inst.addressSize, byteCount, decrement));

            if (isRep) {
                SetCount(GetCount() - 1);
                // REPE: stop if ZF=0; REPNE: stop if ZF=1
                if (hasRep && !m_state.eflags.ZF()) break;
                if (hasRepNE && m_state.eflags.ZF()) break;
            }
        }
        return ErrorCode::Success;
    }

    // === SCAS (0xAE byte, 0xAF word/dword/qword) ===
    if (op == 0xAE || op == 0xAF) {
        uint64_t iterations = isRep ? GetCount() : 1;
        if (isRep && iterations == 0) return ErrorCode::Success;
        if (iterations > kMaxRepIterations) iterations = kMaxRepIterations;

        uint64_t accum = m_state.GetRegBySize(GPR::RAX, elemSize);

        for (uint64_t i = 0; i < iterations; i++) {
            uint64_t val = 0;
            auto err = mem.Read(GetDI(), &val, byteCount);
            if (err != ErrorCode::Success) return err;

            uint64_t diff = accum - val;
            switch (elemSize) {
                case OperandSize::Size8:
                    m_state.eflags.UpdateFlagsSub8(static_cast<uint8_t>(accum), static_cast<uint8_t>(val), static_cast<uint8_t>(diff)); break;
                case OperandSize::Size16:
                    m_state.eflags.UpdateFlagsSub16(static_cast<uint16_t>(accum), static_cast<uint16_t>(val), static_cast<uint16_t>(diff)); break;
                case OperandSize::Size32:
                    m_state.eflags.UpdateFlagsSub32(static_cast<uint32_t>(accum), static_cast<uint32_t>(val), static_cast<uint32_t>(diff)); break;
                case OperandSize::Size64:
                    m_state.eflags.UpdateFlagsSub64(accum, val, diff); break;
            }

            SetDI(AdvanceStringIndex(GetDI(), inst.addressSize, byteCount, decrement));

            if (isRep) {
                SetCount(GetCount() - 1);
                if (hasRep && !m_state.eflags.ZF()) break;
                if (hasRepNE && m_state.eflags.ZF()) break;
            }
        }
        return ErrorCode::Success;
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
