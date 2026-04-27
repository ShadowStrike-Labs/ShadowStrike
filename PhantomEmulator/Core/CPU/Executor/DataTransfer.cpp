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

namespace {

[[nodiscard]] bool HasOperands(const DecodedInstruction& inst, uint8_t count) noexcept {
    return inst.operandCount >= count;
}

[[nodiscard]] ErrorCode OperandSizeBytes(OperandSize size, uint32_t& bytes) noexcept {
    switch (size) {
        case OperandSize::Size16: bytes = 2; return ErrorCode::Success;
        case OperandSize::Size32: bytes = 4; return ErrorCode::Success;
        case OperandSize::Size64: bytes = 8; return ErrorCode::Success;
        default: return ErrorCode::InvalidOperandSize;
    }
}

[[nodiscard]] uint64_t ZeroExtendMoveSource(uint64_t value, uint8_t opcode) noexcept {
    return (opcode == 0xB6) ? (value & 0xFFu) : (value & 0xFFFFu);
}

} // namespace

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
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            return WriteOperand(inst.Op(0), inst, mem, val);
        }

        // === LEA r, m (0x8D) ===
        if (op == 0x8D) {
            if (!HasOperands(inst, 2) || !inst.Op(1).IsMemory()) return ErrorCode::InvalidOperandSize;
            // LEA does NOT access memory — just computes effective address
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            // In 32-bit operand size, truncate to 32 bits
            if (size == OperandSize::Size32) addr &= 0xFFFFFFFF;
            if (size == OperandSize::Size16) addr &= 0xFFFF;
            return WriteOperand(inst.Op(0), inst, mem, addr);
        }

        // === XCHG r, r/m (0x86, 0x87) or XCHG eAX, r (0x91-0x97) ===
        if (op == 0x86 || op == 0x87 || (op >= 0x91 && op <= 0x97)) {
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
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
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
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
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            return WriteOperand(inst.Op(0), inst, mem, ZeroExtendMoveSource(val, op));
        }

        // === MOVSX (0F BE: r, r/m8; 0F BF: r, r/m16) ===
        if (op == 0xBE || op == 0xBF) {
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;

            OperandSize srcSize = (op == 0xBE) ? OperandSize::Size8 : OperandSize::Size16;
            uint64_t result = SignExtendToSize(val, srcSize, size);
            return WriteOperand(inst.Op(0), inst, mem, result);
        }

        // === CMOVcc (0F 40 - 0F 4F) ===
        if (op >= 0x40 && op <= 0x4F) {
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            uint8_t cc = op & 0x0F;
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            if (m_state.eflags.EvaluateCondition(cc)) {
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
                val = PHANTOM_BSWAP64(val);
                m_state.SetReg64(reg, val);
            } else {
                uint32_t val = m_state.GetReg32(reg);
                val = PHANTOM_BSWAP32(val);
                m_state.SetReg32(reg, val);
            }
            return ErrorCode::Success;
        }
    }

    // ========================================================================
    // ThreeByte38 map (0F 38 xx) — MOVBE
    // ========================================================================
    // MOVBE performs a byte-swap load or store. Intel CPUID leaf 1 ECX bit 22.
    // Encoding: NP 0F 38 F0 /r (load), NP 0F 38 F1 /r (store).
    // Operand-size override (66h) selects 16-bit form.
    // REX.W selects 64-bit form.
    if (inst.opcodeMap == OpcodeMap::ThreeByte38) {
        // === MOVBE r, m (0F 38 F0) — Load with byte swap ===
        if (op == 0xF0) {
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            if (!inst.Op(1).IsMemory()) return ErrorCode::InvalidOperandSize;
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(1), inst);
            uint64_t val = 0;
            uint32_t bytes = 0;
            auto sizeErr = OperandSizeBytes(size, bytes);
            if (sizeErr != ErrorCode::Success) return sizeErr;
            auto err = mem.Read(addr, reinterpret_cast<uint8_t*>(&val), bytes);
            if (err != ErrorCode::Success) return err;
            switch (size) {
                case OperandSize::Size16:
                    val = PHANTOM_BSWAP16(static_cast<uint16_t>(val));
                    break;
                case OperandSize::Size32:
                    val = PHANTOM_BSWAP32(static_cast<uint32_t>(val));
                    break;
                case OperandSize::Size64:
                    val = PHANTOM_BSWAP64(val);
                    break;
                default: break;
            }
            return WriteOperand(inst.Op(0), inst, mem, val);
        }

        // === MOVBE m, r (0F 38 F1) — Store with byte swap ===
        if (op == 0xF1) {
            if (!HasOperands(inst, 2)) return ErrorCode::InvalidOperandSize;
            if (!inst.Op(0).IsMemory()) return ErrorCode::InvalidOperandSize;
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(1), inst, mem, val);
            if (err != ErrorCode::Success) return err;
            switch (size) {
                case OperandSize::Size16:
                    val = PHANTOM_BSWAP16(static_cast<uint16_t>(val));
                    break;
                case OperandSize::Size32:
                    val = PHANTOM_BSWAP32(static_cast<uint32_t>(val));
                    break;
                case OperandSize::Size64:
                    val = PHANTOM_BSWAP64(val);
                    break;
                default: return ErrorCode::InvalidOperandSize;
            }
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            uint32_t bytes = 0;
            auto sizeErr = OperandSizeBytes(size, bytes);
            if (sizeErr != ErrorCode::Success) return sizeErr;
            return mem.Write(addr, reinterpret_cast<const uint8_t*>(&val), bytes);
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
