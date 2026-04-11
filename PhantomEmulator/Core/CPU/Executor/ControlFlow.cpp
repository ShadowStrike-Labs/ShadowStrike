/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ControlFlow.cpp — JMP, Jcc, CALL, RET, LOOP, SETcc
 *
 * CET shadow stack integration: CALL pushes return addresses to the shadow
 * stack, RET validates against it, and indirect JMP/CALL set the
 * waitForEndBranch flag for IBT enforcement.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"

namespace Phantom {

// ============================================================================
// Shadow Stack Helpers (inlined for hot-path performance)
// ============================================================================

static inline void ShadowStackPush(CPUState& state, uint64_t returnAddr) noexcept {
    auto& ss = state.shadowStack;
    if (!ss.enabled) return;
    // Silently wrap on overflow — real hardware would #CP, but for
    // emulation analysis we keep running to observe full behavior.
    [[maybe_unused]] bool ok = ss.Push(returnAddr);
}

static inline ErrorCode ShadowStackValidateReturn(CPUState& state, uint64_t retAddr) noexcept {
    auto& ss = state.shadowStack;
    if (!ss.enabled) return ErrorCode::Success;

    uint64_t expectedAddr = 0;
    if (!ss.Pop(expectedAddr)) {
        // Shadow stack underflow — suspicious but not necessarily malicious
        // (could be entry-point return). Record the violation for analysis.
        ++ss.violations;
        return ErrorCode::Success;
    }

    if (expectedAddr != retAddr) {
        // Shadow stack mismatch — potential ROP detected
        ++ss.violations;
        return ErrorCode::ControlProtectionFault;
    }
    return ErrorCode::Success;
}

static inline void SetWaitForEndBranch(CPUState& state) noexcept {
    if (state.shadowStack.ibtEnabled) {
        state.shadowStack.waitForEndBranch = true;
    }
}

ErrorCode CPU::ExecuteControlFlow(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;
    OperandSize pushSize = m_state.Is64Bit() ? OperandSize::Size64 : OperandSize::Size32;

    if (inst.opcodeMap == OpcodeMap::OneByte) {

        // === Jcc short (0x70 - 0x7F) ===
        if (op >= 0x70 && op <= 0x7F) {
            uint8_t cc = op & 0x0F;
            if (m_state.eflags.EvaluateCondition(cc)) {
                m_state.SetRIP(inst.NextRIP() + inst.Op(0).rel.offset);
            } else {
                m_state.AdvanceRIP(inst.length);
            }
            return ErrorCode::Success;
        }

        // === JMP rel8 (0xEB) ===
        if (op == 0xEB) {
            m_state.SetRIP(inst.NextRIP() + inst.Op(0).rel.offset);
            return ErrorCode::Success;
        }

        // === JMP rel32 (0xE9) ===
        if (op == 0xE9) {
            m_state.SetRIP(inst.NextRIP() + inst.Op(0).rel.offset);
            return ErrorCode::Success;
        }

        // === CALL rel32 (0xE8) ===
        if (op == 0xE8) {
            GuestAddress returnAddr = inst.NextRIP();
            auto err = StackPush(mem, returnAddr, pushSize);
            if (err != ErrorCode::Success) return err;
            ShadowStackPush(m_state, returnAddr);
            m_state.SetRIP(inst.NextRIP() + inst.Op(0).rel.offset);
            return ErrorCode::Success;
        }

        // === RET near (0xC3) ===
        if (op == 0xC3) {
            uint64_t retAddr = 0;
            auto err = StackPop(mem, retAddr, pushSize);
            if (err != ErrorCode::Success) return err;
            err = ShadowStackValidateReturn(m_state, retAddr);
            if (err != ErrorCode::Success) return err;
            m_state.SetRIP(retAddr);
            return ErrorCode::Success;
        }

        // === RET near imm16 (0xC2) — pop return address, then add imm16 to RSP ===
        if (op == 0xC2) {
            uint64_t retAddr = 0;
            auto err = StackPop(mem, retAddr, pushSize);
            if (err != ErrorCode::Success) return err;
            err = ShadowStackValidateReturn(m_state, retAddr);
            if (err != ErrorCode::Success) return err;
            uint16_t stackAdj = static_cast<uint16_t>(inst.immediate & 0xFFFF);
            m_state.SetReg64(GPR::RSP, m_state.RSP() + stackAdj);
            m_state.SetRIP(retAddr);
            return ErrorCode::Success;
        }

        // === LOOP/LOOPcc/JCXZ (0xE0-0xE3) ===
        if (op >= 0xE0 && op <= 0xE3) {
            int64_t offset = inst.Op(0).rel.offset;
            GuestAddress target = inst.NextRIP() + offset;
            GuestAddress fallthrough = inst.NextRIP();

            if (op == 0xE3) {
                // JCXZ / JECXZ / JRCXZ — jump if CX/ECX/RCX == 0
                uint64_t counter = 0;
                if (inst.addressSize == AddressSize::Addr16) counter = m_state.GetReg16(GPR::RCX);
                else if (inst.addressSize == AddressSize::Addr32) counter = m_state.GetReg32(GPR::RCX);
                else counter = m_state.GetReg64(GPR::RCX);

                m_state.SetRIP(counter == 0 ? target : fallthrough);
                return ErrorCode::Success;
            }

            // LOOP variants: decrement CX/ECX/RCX first
            uint64_t counter = 0;
            if (inst.addressSize == AddressSize::Addr64) {
                counter = m_state.GetReg64(GPR::RCX) - 1;
                m_state.SetReg64(GPR::RCX, counter);
            } else if (inst.addressSize == AddressSize::Addr32) {
                counter = m_state.GetReg32(GPR::RCX) - 1;
                m_state.SetReg32(GPR::RCX, static_cast<uint32_t>(counter));
                counter = static_cast<uint32_t>(counter);
            } else {
                counter = m_state.GetReg16(GPR::RCX) - 1;
                m_state.SetReg16(GPR::RCX, static_cast<uint16_t>(counter));
                counter = static_cast<uint16_t>(counter);
            }

            bool branch = false;
            switch (op) {
                case 0xE2: branch = (counter != 0); break;                           // LOOP
                case 0xE1: branch = (counter != 0) && m_state.eflags.ZF(); break;    // LOOPE
                case 0xE0: branch = (counter != 0) && !m_state.eflags.ZF(); break;   // LOOPNE
            }

            m_state.SetRIP(branch ? target : fallthrough);
            return ErrorCode::Success;
        }

        // === JMP/CALL r/m (0xFF ext 2=CALL, ext 4=JMP) ===
        if (op == 0xFF) {
            uint8_t ext = inst.opcodeExt;

            if (ext == 4) {
                // JMP r/m — indirect jump
                uint64_t target = 0;
                auto err = ReadOperand(inst.Op(0), inst, mem, target);
                if (err != ErrorCode::Success) return err;
                SetWaitForEndBranch(m_state);
                m_state.SetRIP(target);
                return ErrorCode::Success;
            }

            if (ext == 2) {
                // CALL r/m — indirect call
                uint64_t target = 0;
                auto err = ReadOperand(inst.Op(0), inst, mem, target);
                if (err != ErrorCode::Success) return err;
                GuestAddress returnAddr = inst.NextRIP();
                err = StackPush(mem, returnAddr, pushSize);
                if (err != ErrorCode::Success) return err;
                ShadowStackPush(m_state, returnAddr);
                SetWaitForEndBranch(m_state);
                m_state.SetRIP(target);
                return ErrorCode::Success;
            }
        }
    }

    // === Two-byte opcodes ===
    if (inst.opcodeMap == OpcodeMap::TwoByte) {

        // === Jcc near (0F 80 - 0F 8F) ===
        if (op >= 0x80 && op <= 0x8F) {
            uint8_t cc = op & 0x0F;
            if (m_state.eflags.EvaluateCondition(cc)) {
                m_state.SetRIP(inst.NextRIP() + inst.Op(0).rel.offset);
            } else {
                m_state.AdvanceRIP(inst.length);
            }
            return ErrorCode::Success;
        }

        // === SETcc (0F 90 - 0F 9F) ===
        if (op >= 0x90 && op <= 0x9F) {
            uint8_t cc = op & 0x0F;
            uint64_t val = m_state.eflags.EvaluateCondition(cc) ? 1 : 0;
            m_state.AdvanceRIP(inst.length);
            return WriteOperand(inst.Op(0), inst, mem, val);
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
