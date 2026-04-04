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

ErrorCode CPU::ExecuteString(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize elemSize = inst.operandSize;

    // For string ops with 0xA4/0xA5 the operand size selects byte/word/dword/qword
    // 0xA4/0xAA/0xAC/0xA6/0xAE = byte variants (force Size8)
    if (op == 0xA4 || op == 0xA6 || op == 0xAA || op == 0xAC || op == 0xAE) {
        elemSize = OperandSize::Size8;
    }

    uint32_t byteCount = static_cast<uint32_t>(elemSize);
    int64_t delta = m_state.eflags.DF() ? -static_cast<int64_t>(byteCount)
                                         : static_cast<int64_t>(byteCount);

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

            SetSI(GetSI() + delta);
            SetDI(GetDI() + delta);
        }

        if (isRep) SetCount(GetCount() - iterations);
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
            SetDI(GetDI() + delta);
        }

        if (isRep) SetCount(GetCount() - iterations);
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
            SetSI(GetSI() + delta);
        }
        // Only last value is written to AL/AX/EAX/RAX
        m_state.SetRegBySize(GPR::RAX, val, elemSize);

        if (isRep) SetCount(GetCount() - iterations);
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

            SetSI(GetSI() + delta);
            SetDI(GetDI() + delta);

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

            SetDI(GetDI() + delta);

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
