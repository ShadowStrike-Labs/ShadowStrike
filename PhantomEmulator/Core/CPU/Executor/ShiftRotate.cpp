/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ShiftRotate.cpp — SHL, SHR, SAR, ROL, ROR, RCL, RCR, SHLD, SHRD
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"

namespace Phantom {

namespace {

// Returns the count mask for shift operations per size
[[nodiscard]] uint8_t ShiftCountMask(OperandSize size) noexcept {
    return (size == OperandSize::Size64) ? 63 : 31;
}

[[nodiscard]] uint8_t OperandBitWidth(OperandSize size) noexcept {
    return static_cast<uint8_t>(static_cast<uint8_t>(size) * 8u);
}

[[nodiscard]] bool HasOperands(const DecodedInstruction& inst, uint8_t count) noexcept {
    return inst.operandCount >= count;
}

[[nodiscard]] bool IsSupportedShiftSize(OperandSize size) noexcept {
    return size == OperandSize::Size8 ||
           size == OperandSize::Size16 ||
           size == OperandSize::Size32 ||
           size == OperandSize::Size64;
}

[[nodiscard]] bool IsSupportedDoublePrecisionShiftSize(OperandSize size) noexcept {
    return size == OperandSize::Size16 ||
           size == OperandSize::Size32 ||
           size == OperandSize::Size64;
}

[[nodiscard]] uint64_t MaskForSize(OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  return 0xFFu;
        case OperandSize::Size16: return 0xFFFFu;
        case OperandSize::Size32: return 0xFFFFFFFFull;
        case OperandSize::Size64: return 0xFFFFFFFFFFFFFFFFull;
        default: return 0;
    }
}

[[nodiscard]] uint64_t ArithmeticShiftRight(uint64_t value, uint8_t count, OperandSize size) noexcept {
    const uint8_t bits = OperandBitWidth(size);
    const uint64_t masked = value & MaskForSize(size);
    const bool negative = ((masked >> (bits - 1u)) & 1u) != 0;

    if (count >= bits) {
        return negative ? MaskForSize(size) : 0;
    }

    uint64_t result = masked >> count;
    if (negative && count > 0) {
        result |= (MaskForSize(size) << (bits - count)) & MaskForSize(size);
    }
    return result & MaskForSize(size);
}

[[nodiscard]] uint8_t RotateThroughCarryCount(uint8_t count, OperandSize size) noexcept {
    if (size == OperandSize::Size8) return static_cast<uint8_t>(count % 9u);
    if (size == OperandSize::Size16) return static_cast<uint8_t>(count % 17u);
    return count;
}

void UpdateShiftResultFlags(EFlags& flags, uint64_t result, OperandSize size) noexcept {
    switch (size) {
        case OperandSize::Size8:  flags.UpdateSZP8(static_cast<uint8_t>(result)); break;
        case OperandSize::Size16: flags.UpdateSZP16(static_cast<uint16_t>(result)); break;
        case OperandSize::Size32: flags.UpdateSZP32(static_cast<uint32_t>(result)); break;
        case OperandSize::Size64: flags.UpdateSZP64(result); break;
        default: break;
    }
}

} // namespace

ErrorCode CPU::ExecuteShiftRotate(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    // === 1-byte opcodes: C0/C1 (imm8), D0/D1 (1), D2/D3 (CL) ===
    if (inst.opcodeMap == OpcodeMap::OneByte &&
        (op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3)))
    {
        uint8_t ext = inst.opcodeExt; // ROL=0, ROR=1, RCL=2, RCR=3, SHL=4, SHR=5, SAL=6(=SHL), SAR=7
        const uint8_t requiredOperands = (op == 0xC0 || op == 0xC1) ? 2u : 1u;
        if (ext > 7 || !HasOperands(inst, requiredOperands) || !IsSupportedShiftSize(size)) {
            return ErrorCode::InvalidOperandSize;
        }

        uint64_t val = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, val);
        if (err != ErrorCode::Success) return err;

        // Determine shift count
        uint8_t count = 0;
        if (op == 0xD0 || op == 0xD1) {
            count = 1;
        } else if (op == 0xD2 || op == 0xD3) {
            count = m_state.GetReg8(GPR::RCX);
        } else {
            uint64_t immVal = 0;
            err = ReadOperand(inst.Op(1), inst, mem, immVal);
            if (err != ErrorCode::Success) return err;
            count = static_cast<uint8_t>(immVal);
        }

        count &= ShiftCountMask(size);
        if (count == 0) return ErrorCode::Success; // No operation when count=0

        uint8_t bits = OperandBitWidth(size);
        uint64_t result = val;

        switch (ext) {
            case 4: // SHL / SAL
            case 6: {
                result = (count >= bits) ? 0 : (val << count);
                result = MaskToSize(result, size);

                UpdateShiftResultFlags(m_state.eflags, result, size);
                // CF = last bit shifted out
                if (count <= bits) {
                    m_state.eflags.SetCF(((val >> (bits - count)) & 1) != 0);
                } else {
                    m_state.eflags.SetCF(false);
                }
                if (count == 1) {
                    // OF defined only for count=1: OF = MSB(result) XOR CF
                    bool msb = ((result >> (bits - 1)) & 1) != 0;
                    m_state.eflags.SetOF(msb != m_state.eflags.CF());
                }
                break;
            }

            case 5: { // SHR
                // CF = bit count-1 of source
                if (count <= bits) {
                    m_state.eflags.SetCF(((val >> (count - 1)) & 1) != 0);
                } else {
                    m_state.eflags.SetCF(false);
                }
                result = (count >= bits) ? 0 : (val >> count);
                result = MaskToSize(result, size);

                UpdateShiftResultFlags(m_state.eflags, result, size);
                if (count == 1) {
                    m_state.eflags.SetOF(((val >> (bits - 1)) & 1) != 0);
                }
                break;
            }

            case 7: { // SAR (arithmetic right shift — preserves sign)
                if (count <= bits) {
                    m_state.eflags.SetCF(((val >> (count - 1)) & 1) != 0);
                } else {
                    m_state.eflags.SetCF(((val >> (bits - 1)) & 1) != 0);
                }
                result = ArithmeticShiftRight(val, count, size);
                UpdateShiftResultFlags(m_state.eflags, result, size);
                if (count == 1) m_state.eflags.SetOF(false); // OF=0 for SAR count=1
                break;
            }

            case 0: { // ROL
                uint8_t cnt = count % bits;
                if (cnt > 0) {
                    result = (val << cnt) | (val >> (bits - cnt));
                    result = MaskToSize(result, size);
                }
                m_state.eflags.SetCF((result & 1) != 0);
                if (count == 1) {
                    bool msb = ((result >> (bits - 1)) & 1) != 0;
                    m_state.eflags.SetOF(msb ^ m_state.eflags.CF());
                }
                break;
            }

            case 1: { // ROR
                uint8_t cnt = count % bits;
                if (cnt > 0) {
                    result = (val >> cnt) | (val << (bits - cnt));
                    result = MaskToSize(result, size);
                }
                m_state.eflags.SetCF(((result >> (bits - 1)) & 1) != 0);
                if (count == 1) {
                    bool msb = ((result >> (bits - 1)) & 1) != 0;
                    bool msb1 = ((result >> (bits - 2)) & 1) != 0;
                    m_state.eflags.SetOF(msb ^ msb1);
                }
                break;
            }

            case 2: { // RCL (rotate through carry left)
                const uint8_t rotateCount = RotateThroughCarryCount(count, size);
                if (rotateCount == 0) return ErrorCode::Success;
                for (uint8_t i = 0; i < rotateCount; i++) {
                    bool oldCF = m_state.eflags.CF();
                    m_state.eflags.SetCF(((val >> (bits - 1)) & 1) != 0);
                    val = (val << 1) | (oldCF ? 1 : 0);
                    val = MaskToSize(val, size);
                }
                result = val;
                if (rotateCount == 1) {
                    bool msb = ((result >> (bits - 1)) & 1) != 0;
                    m_state.eflags.SetOF(msb ^ m_state.eflags.CF());
                }
                break;
            }

            case 3: { // RCR (rotate through carry right)
                const uint8_t rotateCount = RotateThroughCarryCount(count, size);
                if (rotateCount == 0) return ErrorCode::Success;
                for (uint8_t i = 0; i < rotateCount; i++) {
                    bool oldCF = m_state.eflags.CF();
                    m_state.eflags.SetCF((val & 1) != 0);
                    val = (val >> 1) | (oldCF ? (1ULL << (bits - 1)) : 0);
                    val = MaskToSize(val, size);
                }
                result = val;
                if (rotateCount == 1) {
                    bool msb = ((result >> (bits - 1)) & 1) != 0;
                    bool msb1 = ((result >> (bits - 2)) & 1) != 0;
                    m_state.eflags.SetOF(msb ^ msb1);
                }
                break;
            }

            default:
                return ErrorCode::UnimplementedOpcode;
        }

        return WriteOperand(inst.Op(0), inst, mem, result);
    }

    // === SHLD / SHRD (0F A4/A5/AC/AD) ===
    if (inst.opcodeMap == OpcodeMap::TwoByte) {
        bool isSHLD = (op == 0xA4 || op == 0xA5);
        bool isSHRD = (op == 0xAC || op == 0xAD);

        if (isSHLD || isSHRD) {
            const uint8_t requiredOperands = (op == 0xA4 || op == 0xAC) ? 3u : 2u;
            if (!HasOperands(inst, requiredOperands) || !IsSupportedDoublePrecisionShiftSize(size)) {
                return ErrorCode::InvalidOperandSize;
            }

            uint64_t dst = 0, src = 0;
            auto err = ReadOperand(inst.Op(0), inst, mem, dst);
            if (err != ErrorCode::Success) return err;
            err = ReadOperand(inst.Op(1), inst, mem, src);
            if (err != ErrorCode::Success) return err;

            uint8_t count = 0;
            if (op == 0xA5 || op == 0xAD) {
                count = m_state.GetReg8(GPR::RCX);
            } else {
                uint64_t immVal = 0;
                err = ReadOperand(inst.Op(2), inst, mem, immVal);
                if (err != ErrorCode::Success) return err;
                count = static_cast<uint8_t>(immVal);
            }

            count &= ShiftCountMask(size);
            if (count == 0) return ErrorCode::Success;

            uint8_t bits = static_cast<uint8_t>(size) * 8;
            uint64_t result = 0;

            if (count >= bits) {
                // Architecturally undefined on real hardware; keep emulator state deterministic.
                result = 0;
            } else if (isSHLD) {
                result = (dst << count) | (src >> (bits - count));
            } else {
                result = (dst >> count) | (src << (bits - count));
            }

            result = MaskToSize(result, size);

            UpdateShiftResultFlags(m_state.eflags, result, size);

            if (isSHLD) {
                if (count <= bits) {
                    m_state.eflags.SetCF(((dst >> (bits - count)) & 1) != 0);
                } else {
                    m_state.eflags.SetCF(false);
                }
            } else {
                if (count <= bits) {
                    m_state.eflags.SetCF(((dst >> (count - 1)) & 1) != 0);
                } else {
                    m_state.eflags.SetCF(false);
                }
            }

            return WriteOperand(inst.Op(0), inst, mem, result);
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
