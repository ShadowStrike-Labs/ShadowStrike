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

// Returns the count mask for shift operations per size
static uint8_t ShiftCountMask(OperandSize size) noexcept {
    return (size == OperandSize::Size64) ? 63 : 31;
}

ErrorCode CPU::ExecuteShiftRotate(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    // === 1-byte opcodes: C0/C1 (imm8), D0/D1 (1), D2/D3 (CL) ===
    if (inst.opcodeMap == OpcodeMap::OneByte &&
        (op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3)))
    {
        uint8_t ext = inst.opcodeExt; // ROL=0, ROR=1, RCL=2, RCR=3, SHL=4, SHR=5, SAL=6(=SHL), SAR=7
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

        uint8_t bits = static_cast<uint8_t>(size) * 8;
        uint64_t result = val;

        switch (ext) {
            case 4: // SHL / SAL
            case 6: {
                result = val << count;
                result = MaskToSize(result, size);

                switch (size) {
                    case OperandSize::Size8:  m_state.eflags.UpdateSZP8(static_cast<uint8_t>(result)); break;
                    case OperandSize::Size16: m_state.eflags.UpdateSZP16(static_cast<uint16_t>(result)); break;
                    case OperandSize::Size32: m_state.eflags.UpdateSZP32(static_cast<uint32_t>(result)); break;
                    case OperandSize::Size64: m_state.eflags.UpdateSZP64(result); break;
                }
                // CF = last bit shifted out
                m_state.eflags.SetCF(((val >> (bits - count)) & 1) != 0);
                if (count == 1) {
                    // OF defined only for count=1: OF = MSB(result) XOR CF
                    bool msb = ((result >> (bits - 1)) & 1) != 0;
                    m_state.eflags.SetOF(msb != m_state.eflags.CF());
                }
                break;
            }

            case 5: { // SHR
                // CF = bit count-1 of source
                m_state.eflags.SetCF(((val >> (count - 1)) & 1) != 0);
                result = val >> count;
                result = MaskToSize(result, size);

                switch (size) {
                    case OperandSize::Size8:  m_state.eflags.UpdateSZP8(static_cast<uint8_t>(result)); break;
                    case OperandSize::Size16: m_state.eflags.UpdateSZP16(static_cast<uint16_t>(result)); break;
                    case OperandSize::Size32: m_state.eflags.UpdateSZP32(static_cast<uint32_t>(result)); break;
                    case OperandSize::Size64: m_state.eflags.UpdateSZP64(result); break;
                }
                if (count == 1) {
                    m_state.eflags.SetOF(((val >> (bits - 1)) & 1) != 0);
                }
                break;
            }

            case 7: { // SAR (arithmetic right shift — preserves sign)
                m_state.eflags.SetCF(((val >> (count - 1)) & 1) != 0);

                switch (size) {
                    case OperandSize::Size8: {
                        int8_t sVal = static_cast<int8_t>(val);
                        result = static_cast<uint8_t>(sVal >> count);
                        m_state.eflags.UpdateSZP8(static_cast<uint8_t>(result));
                        break;
                    }
                    case OperandSize::Size16: {
                        int16_t sVal = static_cast<int16_t>(val);
                        result = static_cast<uint16_t>(sVal >> count);
                        m_state.eflags.UpdateSZP16(static_cast<uint16_t>(result));
                        break;
                    }
                    case OperandSize::Size32: {
                        int32_t sVal = static_cast<int32_t>(val);
                        result = static_cast<uint32_t>(sVal >> count);
                        m_state.eflags.UpdateSZP32(static_cast<uint32_t>(result));
                        break;
                    }
                    case OperandSize::Size64: {
                        int64_t sVal = static_cast<int64_t>(val);
                        result = static_cast<uint64_t>(sVal >> count);
                        m_state.eflags.UpdateSZP64(result);
                        break;
                    }
                }
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
                for (uint8_t i = 0; i < count; i++) {
                    bool oldCF = m_state.eflags.CF();
                    m_state.eflags.SetCF(((val >> (bits - 1)) & 1) != 0);
                    val = (val << 1) | (oldCF ? 1 : 0);
                    val = MaskToSize(val, size);
                }
                result = val;
                if (count == 1) {
                    bool msb = ((result >> (bits - 1)) & 1) != 0;
                    m_state.eflags.SetOF(msb ^ m_state.eflags.CF());
                }
                break;
            }

            case 3: { // RCR (rotate through carry right)
                for (uint8_t i = 0; i < count; i++) {
                    bool oldCF = m_state.eflags.CF();
                    m_state.eflags.SetCF((val & 1) != 0);
                    val = (val >> 1) | (oldCF ? (1ULL << (bits - 1)) : 0);
                    val = MaskToSize(val, size);
                }
                result = val;
                if (count == 1) {
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
                // Undefined behavior on real hardware — we zero it
                result = 0;
            } else if (isSHLD) {
                result = (dst << count) | (src >> (bits - count));
            } else {
                result = (dst >> count) | (src << (bits - count));
            }

            result = MaskToSize(result, size);

            switch (size) {
                case OperandSize::Size8:  m_state.eflags.UpdateSZP8(static_cast<uint8_t>(result)); break;
                case OperandSize::Size16: m_state.eflags.UpdateSZP16(static_cast<uint16_t>(result)); break;
                case OperandSize::Size32: m_state.eflags.UpdateSZP32(static_cast<uint32_t>(result)); break;
                case OperandSize::Size64: m_state.eflags.UpdateSZP64(result); break;
            }

            if (isSHLD) {
                m_state.eflags.SetCF(((dst >> (bits - count)) & 1) != 0);
            } else {
                m_state.eflags.SetCF(((dst >> (count - 1)) & 1) != 0);
            }

            return WriteOperand(inst.Op(0), inst, mem, result);
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
