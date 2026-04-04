/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DataTransfer.cpp — MOV, MOVZX, MOVSX, LEA, XCHG, BSWAP,
 *                    CMOVcc, CBW/CWDE/CDQE, CWD/CDQ/CQO, MOVSXD
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "../../../Common/Platform.hpp"

namespace Phantom {

ErrorCode CPU::ExecuteDataTransfer(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    // === MOV r/m, r (0x88, 0x89) / MOV r, r/m (0x8A, 0x8B) ===
    // === MOV r/m, imm (0xC6, 0xC7) ===
    // === MOV r, imm (0xB0-0xBF) ===
    // === MOV AL/AX, moffs (0xA0, 0xA1) / MOV moffs, AL/AX (0xA2, 0xA3) ===
    // === MOV Sreg (0x8C, 0x8E) ===
    if (inst.opcodeMap == OpcodeMap::OneByte) {
        bool isMOV = false;
        if ((op >= 0x88 && op <= 0x8B) || op == 0x8C || op == 0x8E ||
            (op >= 0xA0 && op <= 0xA3) || (op >= 0xB0 && op <= 0xBF) ||
            op == 0xC6 || op == 0xC7)
        {
            isMOV = true;
        }

        if (isMOV) {
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            return WriteOperand(inst.Op(0), inst, mem, val);
        }

        // === LEA r, m (0x8D) ===
        if (op == 0x8D) {
            // LEA does NOT access memory — just computes effective address
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            // In 32-bit operand size, truncate to 32 bits
            if (size == OperandSize::Size32) addr &= 0xFFFFFFFF;
            if (size == OperandSize::Size16) addr &= 0xFFFF;
            return WriteOperand(inst.Op(0), inst, mem, addr);
        }

        // === XCHG r, r/m (0x86, 0x87) or XCHG eAX, r (0x91-0x97) ===
        if (op == 0x86 || op == 0x87 || (op >= 0x91 && op <= 0x97)) {
            uint64_t a = 0, b = 0;
            auto err = ReadOperand(inst.Op(0), inst, mem, a);
            if (err != ErrorCode::Success) return err;
            err = ReadOperand(inst.Op(1), inst, mem, b);
            if (err != ErrorCode::Success) return err;

            err = WriteOperand(inst.Op(0), inst, mem, b);
            if (err != ErrorCode::Success) return err;
            return WriteOperand(inst.Op(1), inst, mem, a);
        }

        // === CBW/CWDE/CDQE (0x98) — sign-extend AL/AX/EAX → AX/EAX/RAX ===
        if (op == 0x98) {
            switch (size) {
                case OperandSize::Size16: {
                    int8_t al = static_cast<int8_t>(m_state.GetReg8(GPR::RAX));
                    m_state.SetReg16(GPR::RAX, static_cast<uint16_t>(static_cast<int16_t>(al)));
                    break;
                }
                case OperandSize::Size32: {
                    int16_t ax = static_cast<int16_t>(m_state.GetReg16(GPR::RAX));
                    m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(static_cast<int32_t>(ax)));
                    break;
                }
                case OperandSize::Size64: {
                    int32_t eax = static_cast<int32_t>(m_state.GetReg32(GPR::RAX));
                    m_state.SetReg64(GPR::RAX, static_cast<uint64_t>(static_cast<int64_t>(eax)));
                    break;
                }
                default: break;
            }
            return ErrorCode::Success;
        }

        // === CWD/CDQ/CQO (0x99) — sign-extend AX/EAX/RAX → DX:AX/EDX:EAX/RDX:RAX ===
        if (op == 0x99) {
            switch (size) {
                case OperandSize::Size16: {
                    int16_t ax = static_cast<int16_t>(m_state.GetReg16(GPR::RAX));
                    m_state.SetReg16(GPR::RDX, ax < 0 ? 0xFFFF : 0);
                    break;
                }
                case OperandSize::Size32: {
                    int32_t eax = static_cast<int32_t>(m_state.GetReg32(GPR::RAX));
                    m_state.SetReg32(GPR::RDX, eax < 0 ? 0xFFFFFFFF : 0);
                    break;
                }
                case OperandSize::Size64: {
                    int64_t rax = static_cast<int64_t>(m_state.GetReg64(GPR::RAX));
                    m_state.SetReg64(GPR::RDX, rax < 0 ? 0xFFFFFFFFFFFFFFFFULL : 0);
                    break;
                }
                default: break;
            }
            return ErrorCode::Success;
        }

        // === MOVSXD (0x63 in 64-bit mode) ===
        if (op == 0x63 && m_state.Is64Bit()) {
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            // Sign-extend 32 → 64
            int32_t sVal = static_cast<int32_t>(val);
            return WriteOperand(inst.Op(0), inst, mem,
                                static_cast<uint64_t>(static_cast<int64_t>(sVal)));
        }
    }

    // === Two-byte opcode handlers ===
    if (inst.opcodeMap == OpcodeMap::TwoByte) {

        // === MOVZX (0F B6: r, r/m8; 0F B7: r, r/m16) ===
        if (op == 0xB6 || op == 0xB7) {
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            // Zero-extension happens naturally since val is already zero-extended
            return WriteOperand(inst.Op(0), inst, mem, val);
        }

        // === MOVSX (0F BE: r, r/m8; 0F BF: r, r/m16) ===
        if (op == 0xBE || op == 0xBF) {
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;

            OperandSize srcSize = (op == 0xBE) ? OperandSize::Size8 : OperandSize::Size16;
            uint64_t result = SignExtendToSize(val, srcSize, size);
            return WriteOperand(inst.Op(0), inst, mem, result);
        }

        // === CMOVcc (0F 40 - 0F 4F) ===
        if (op >= 0x40 && op <= 0x4F) {
            uint8_t cc = op & 0x0F;
            if (m_state.eflags.EvaluateCondition(cc)) {
                uint64_t val = 0;
                auto err = ReadOperand(inst.Op(1), inst, mem, val);
                if (err != ErrorCode::Success) return err;
                return WriteOperand(inst.Op(0), inst, mem, val);
            }
            // Condition not met — no change to destination
            return ErrorCode::Success;
        }

        // === BSWAP (0F C8 - 0F CF) ===
        if (op >= 0xC8 && op <= 0xCF) {
            uint8_t regIdx = (op - 0xC8) | (inst.prefixes.rexB ? 8 : 0);
            GPR reg = static_cast<GPR>(regIdx);

            if (size == OperandSize::Size64 || inst.prefixes.rexW) {
                uint64_t val = m_state.GetReg64(reg);
                val = Platform::ByteSwap64(val);
                m_state.SetReg64(reg, val);
            } else {
                uint32_t val = m_state.GetReg32(reg);
                val = Platform::ByteSwap32(val);
                m_state.SetReg32(reg, val);
            }
            return ErrorCode::Success;
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
