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

ErrorCode CPU::ExecuteFlag(const DecodedInstruction& inst) noexcept {
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
            uint64_t flags = m_state.eflags.Raw();
            flags = (flags & ~0xD5ULL) | (ah & 0xD5);
            m_state.eflags.SetRaw(flags);
            return ErrorCode::Success;
        }

        case 0x9F: { // LAHF: low 8 bits of EFLAGS → AH
            uint8_t val = static_cast<uint8_t>(m_state.eflags.Raw() & 0xD5) | 0x02;
            m_state.SetReg8High(4, val);
            return ErrorCode::Success;
        }

        default:
            return ErrorCode::UnimplementedOpcode;
    }
}

} // namespace Phantom
