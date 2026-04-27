/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FlagOps.cpp — CLC, STC, CMC, CLD, STD, CLI, STI, LAHF, SAHF
 *
 * Note: PUSHF/POPF are handled directly in CPU.cpp dispatch since they
 * require VirtualMemory access that ExecuteFlag's signature doesn't provide.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"

namespace Phantom {

namespace {

constexpr uint64_t kLahfSahfWritableMask = 0xD5ULL; // SF, ZF, AF, PF, CF
constexpr uint8_t kReservedFlagBit1 = 0x02;

[[nodiscard]] uint64_t ApplySahfByte(uint64_t currentFlags, uint8_t ah) noexcept {
    return (currentFlags & ~kLahfSahfWritableMask) |
           (static_cast<uint64_t>(ah) & kLahfSahfWritableMask) |
           kReservedFlagBit1;
}

[[nodiscard]] uint8_t MakeLahfByte(uint64_t flags) noexcept {
    return static_cast<uint8_t>((flags & kLahfSahfWritableMask) | kReservedFlagBit1);
}

} // namespace

ErrorCode CPU::ExecuteFlag(const DecodedInstruction& inst) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte) return ErrorCode::UnimplementedOpcode;

    uint8_t op = inst.opcode;

    switch (op) {
        case 0xF5: m_state.eflags.SetCF(!m_state.eflags.CF()); return ErrorCode::Success; // CMC
        case 0xF8: m_state.eflags.SetCF(false); return ErrorCode::Success; // CLC
        case 0xF9: m_state.eflags.SetCF(true);  return ErrorCode::Success; // STC
        case 0xFA: m_state.eflags.SetIF(false); return ErrorCode::Success; // CLI
        case 0xFB: m_state.eflags.SetIF(true);  return ErrorCode::Success; // STI
        case 0xFC: m_state.eflags.SetDF(false); return ErrorCode::Success; // CLD
        case 0xFD: m_state.eflags.SetDF(true);  return ErrorCode::Success; // STD

        case 0x9E: { // SAHF: AH → low 8 bits of EFLAGS (SF, ZF, AF, PF, CF)
            uint8_t ah = m_state.GetReg8High(4); // AH
            m_state.eflags.SetRaw(ApplySahfByte(m_state.eflags.Raw(), ah));
            return ErrorCode::Success;
        }

        case 0x9F: { // LAHF: low 8 bits of EFLAGS → AH
            m_state.SetReg8High(4, MakeLahfByte(m_state.eflags.Raw()));
            return ErrorCode::Success;
        }

        default:
            return ErrorCode::UnimplementedOpcode;
    }
}

} // namespace Phantom
