/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CETOps.cpp — Intel CET (Control-flow Enforcement Technology) instruction
 *              emulation: shadow stack operations + indirect branch tracking.
 *
 * Covers:
 *   Shadow Stack:  INCSSPD/Q, RDSSPD/Q, SAVEPREVSSP, RSTORSSP,
 *                  SETSSBSY, CLRSSBSY, WRSSD/Q, WRUSSD/Q
 *   IBT:           ENDBR32, ENDBR64
 *
 * Dispatch by opcode map + opcode + modrm, matching the established executor
 * pattern used by all other Ops files (opcode-based, not mnemonic-based).
 *
 * CET enforcement is critical for anti-evasion fidelity — modern malware
 * uses ENDBR probing to detect sandboxes, and ROP chains are the primary
 * exploit primitive that CET was designed to stop.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"

namespace Phantom {

ErrorCode CPU::ExecuteCET(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    auto& ss = m_state.shadowStack;

    // ========================================================================
    // TwoByte map: 0F 1E — ENDBR32/64, RDSSPD/Q
    // ========================================================================
    if (inst.opcodeMap == OpcodeMap::TwoByte && inst.opcode == 0x1E) {
        // ENDBR64: F3 0F 1E FA
        if (inst.modrm == 0xFA) {
            ss.waitForEndBranch = false;
            return ErrorCode::Success;
        }
        // ENDBR32: F3 0F 1E FB
        if (inst.modrm == 0xFB) {
            ss.waitForEndBranch = false;
            return ErrorCode::Success;
        }
        // RDSSPD/Q: F3 0F 1E /1 (mod=3)
        if (inst.opcodeExt == 1 && (inst.modrm >> 6) == 3) {
            if (!ss.enabled) return ErrorCode::Success;
            uint8_t reg = inst.Op(0).reg.regIndex;
            if (inst.prefixes.rexW) {
                uint64_t sspVal = static_cast<uint64_t>(ss.pointer) * sizeof(uint64_t);
                m_state.SetReg64(static_cast<GPR>(reg), sspVal);
            } else {
                uint32_t sspVal = ss.pointer * static_cast<uint32_t>(sizeof(uint64_t));
                m_state.SetReg32(static_cast<GPR>(reg), sspVal);
            }
            return ErrorCode::Success;
        }
        return ErrorCode::UnimplementedOpcode;
    }

    // ========================================================================
    // TwoByte map: 0F AE — INCSSPD/Q (F3 /5 mod=3), CLRSSBSY (F3 /6 mem)
    // ========================================================================
    if (inst.opcodeMap == OpcodeMap::TwoByte && inst.opcode == 0xAE) {
        uint8_t ext = inst.opcodeExt;

        // INCSSPD/Q: F3 0F AE /5 (mod=3, register form)
        if (ext == 5 && (inst.modrm >> 6) == 3) {
            if (!ss.enabled) return ErrorCode::Success;
            uint8_t reg = inst.Op(0).reg.regIndex;
            uint64_t count = 0;
            if (inst.prefixes.rexW) {
                count = m_state.GetReg64(static_cast<GPR>(reg)) & 0xFF;
            } else {
                count = m_state.GetReg32(static_cast<GPR>(reg)) & 0xFF;
            }
            if (count == 0) count = 1;  // Intel spec: 0 treated as 1
            for (uint64_t i = 0; i < count && ss.pointer > 0; ++i) {
                --ss.pointer;
            }
            return ErrorCode::Success;
        }

        // CLRSSBSY: F3 0F AE /6 (mod!=3, memory form)
        if (ext == 6 && (inst.modrm >> 6) != 3) {
            if (!ss.enabled) return ErrorCode::Success;
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            uint64_t token = 0;
            auto err = mem.ReadValue<uint64_t>(addr, token);
            if (err != ErrorCode::Success) return err;
            token &= ~1ULL;  // Clear busy bit
            err = mem.WriteValue<uint64_t>(addr, token);
            if (err != ErrorCode::Success) return err;
            ss.busy = false;
            return ErrorCode::Success;
        }
        return ErrorCode::UnimplementedOpcode;
    }

    // ========================================================================
    // TwoByte map: 0F 01 — RSTORSSP, SETSSBSY, SAVEPREVSSP
    // ========================================================================
    if (inst.opcodeMap == OpcodeMap::TwoByte && inst.opcode == 0x01) {

        // SETSSBSY: F3 0F 01 E8
        if (inst.modrm == 0xE8) {
            if (!ss.enabled) return ErrorCode::Success;
            if (ss.busy) {
                ++ss.violations;
                return ErrorCode::ControlProtectionFault;
            }
            ss.busy = true;
            return ErrorCode::Success;
        }

        // SAVEPREVSSP: F3 0F 01 EA
        if (inst.modrm == 0xEA) {
            if (!ss.enabled) return ErrorCode::Success;
            uint64_t token = (static_cast<uint64_t>(ss.pointer) << 1) |
                             (ss.busy ? 1ULL : 0ULL);
            if (!ss.Push(token)) {
                ++ss.violations;
                return ErrorCode::StackOverflow;
            }
            return ErrorCode::Success;
        }

        // RSTORSSP: F3 0F 01 /5 (memory form — mod!=3)
        if (inst.opcodeExt == 5 && (inst.modrm >> 6) != 3) {
            if (!ss.enabled) return ErrorCode::Success;
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            uint64_t token = 0;
            auto err = mem.ReadValue<uint64_t>(addr, token);
            if (err != ErrorCode::Success) return err;

            // Validate: bit 0 must be set (restore token marker)
            if (!(token & 1ULL)) {
                ++ss.violations;
                return ErrorCode::ControlProtectionFault;
            }

            // Write current SSP as previous-SSP token at the restore location
            uint64_t prevToken = (static_cast<uint64_t>(ss.pointer) << 1) | 1ULL;
            err = mem.WriteValue<uint64_t>(addr, prevToken);
            if (err != ErrorCode::Success) return err;

            // Restore SSP
            uint32_t newPointer = static_cast<uint32_t>((token >> 1) & 0xFFFFFFFF);
            if (newPointer > CPUState::kShadowStackMaxDepth)
                newPointer = CPUState::kShadowStackMaxDepth;
            ss.pointer = newPointer;
            return ErrorCode::Success;
        }
        return ErrorCode::UnimplementedOpcode;
    }

    // ========================================================================
    // ThreeByte38 map: WRSSD/Q (NP 0F 38 F6), WRUSSD/Q (66 0F 38 F5)
    // ========================================================================
    if (inst.opcodeMap == OpcodeMap::ThreeByte38) {

        // WRSSD/WRSSQ: NP 0F 38 F6 /r (memory destination, register source)
        if (inst.opcode == 0xF6) {
            if (!ss.enabled) return ErrorCode::Success;
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            uint8_t srcReg = inst.Op(1).reg.regIndex;
            if (inst.prefixes.rexW) {
                uint64_t val = m_state.GetReg64(static_cast<GPR>(srcReg));
                return mem.WriteValue<uint64_t>(addr, val);
            } else {
                uint32_t val = m_state.GetReg32(static_cast<GPR>(srcReg));
                return mem.WriteValue<uint32_t>(addr, val);
            }
        }

        // WRUSSD/WRUSSQ: 66 0F 38 F5 /r (memory destination, register source)
        if (inst.opcode == 0xF5) {
            if (!ss.enabled) return ErrorCode::Success;
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            uint8_t srcReg = inst.Op(1).reg.regIndex;
            if (inst.prefixes.rexW) {
                uint64_t val = m_state.GetReg64(static_cast<GPR>(srcReg));
                return mem.WriteValue<uint64_t>(addr, val);
            } else {
                uint32_t val = m_state.GetReg32(static_cast<GPR>(srcReg));
                return mem.WriteValue<uint32_t>(addr, val);
            }
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
