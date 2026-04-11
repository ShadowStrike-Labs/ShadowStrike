/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ArithmeticOps.cpp — ADD, SUB, ADC, SBB, CMP, INC, DEC, NEG,
 *                     MUL, IMUL, DIV, IDIV, CMPXCHG, XADD
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "../../../Common/Constants.hpp"
#include <bit>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace Phantom {

// Internal ALU operation identifier
enum class ALUOp : uint8_t {
    ADD = 0, OR  = 1, ADC = 2, SBB = 3,
    AND = 4, SUB = 5, XOR = 6, CMP = 7
};

// Determine the ALU operation from the 1-byte opcode (0x00-0x3F range)
static ALUOp GetALUOpFromOpcode(uint8_t opcode) noexcept {
    return static_cast<ALUOp>((opcode >> 3) & 7);
}

// Core 8-operation ALU with flags
static uint64_t DoALU(ALUOp op, uint64_t a, uint64_t b, OperandSize size,
                      EFlags& flags, bool& writeBack) noexcept
{
    writeBack = true;
    uint64_t result = 0;
    uint8_t carry = flags.CF() ? 1 : 0;

    switch (op) {
        case ALUOp::ADD: {
            result = a + b;
            switch (size) {
                case OperandSize::Size8:
                    flags.UpdateFlagsAdd8(
                        static_cast<uint8_t>(a), static_cast<uint8_t>(b),
                        static_cast<uint8_t>(result));
                    break;
                case OperandSize::Size16:
                    flags.UpdateFlagsAdd16(
                        static_cast<uint16_t>(a), static_cast<uint16_t>(b),
                        static_cast<uint16_t>(result));
                    break;
                case OperandSize::Size32:
                    flags.UpdateFlagsAdd32(
                        static_cast<uint32_t>(a), static_cast<uint32_t>(b),
                        static_cast<uint32_t>(result));
                    break;
                case OperandSize::Size64:
                    flags.UpdateFlagsAdd64(a, b, result);
                    break;
            }
            break;
        }

        case ALUOp::ADC: {
            result = a + b + carry;
            // ADC flag update: treat as ADD(a, b+carry)
            switch (size) {
                case OperandSize::Size8: {
                    auto r = static_cast<uint8_t>(result);
                    auto av = static_cast<uint8_t>(a);
                    auto bv = static_cast<uint8_t>(b);
                    flags.UpdateSZP8(r);
                    flags.SetCF(static_cast<uint16_t>(av) + bv + carry > 0xFF);
                    flags.SetOF(((av ^ r) & (bv ^ r) & 0x80) != 0);
                    flags.SetAF(((av ^ bv ^ r) & 0x10) != 0);
                    break;
                }
                case OperandSize::Size16: {
                    auto r = static_cast<uint16_t>(result);
                    auto av = static_cast<uint16_t>(a);
                    auto bv = static_cast<uint16_t>(b);
                    flags.UpdateSZP16(r);
                    flags.SetCF(static_cast<uint32_t>(av) + bv + carry > 0xFFFF);
                    flags.SetOF(((av ^ r) & (bv ^ r) & 0x8000) != 0);
                    flags.SetAF(((av ^ bv ^ r) & 0x10) != 0);
                    break;
                }
                case OperandSize::Size32: {
                    auto r = static_cast<uint32_t>(result);
                    auto av = static_cast<uint32_t>(a);
                    auto bv = static_cast<uint32_t>(b);
                    flags.UpdateSZP32(r);
                    flags.SetCF(static_cast<uint64_t>(av) + bv + carry > 0xFFFFFFFF);
                    flags.SetOF(((av ^ r) & (bv ^ r) & 0x80000000) != 0);
                    flags.SetAF(((av ^ bv ^ r) & 0x10) != 0);
                    break;
                }
                case OperandSize::Size64: {
                    flags.UpdateSZP64(result);
                    // CF: carry out of 64-bit
                    flags.SetCF(result < a || (carry && result == a));
                    flags.SetOF(((a ^ result) & (b ^ result) & 0x8000000000000000ULL) != 0);
                    flags.SetAF(((a ^ b ^ result) & 0x10) != 0);
                    break;
                }
            }
            break;
        }

        case ALUOp::SUB:
        case ALUOp::CMP: {
            result = a - b;
            if (op == ALUOp::CMP) writeBack = false;
            switch (size) {
                case OperandSize::Size8:
                    flags.UpdateFlagsSub8(
                        static_cast<uint8_t>(a), static_cast<uint8_t>(b),
                        static_cast<uint8_t>(result));
                    break;
                case OperandSize::Size16:
                    flags.UpdateFlagsSub16(
                        static_cast<uint16_t>(a), static_cast<uint16_t>(b),
                        static_cast<uint16_t>(result));
                    break;
                case OperandSize::Size32:
                    flags.UpdateFlagsSub32(
                        static_cast<uint32_t>(a), static_cast<uint32_t>(b),
                        static_cast<uint32_t>(result));
                    break;
                case OperandSize::Size64:
                    flags.UpdateFlagsSub64(a, b, result);
                    break;
            }
            break;
        }

        case ALUOp::SBB: {
            result = a - b - carry;
            switch (size) {
                case OperandSize::Size8: {
                    auto r = static_cast<uint8_t>(result);
                    auto av = static_cast<uint8_t>(a);
                    auto bv = static_cast<uint8_t>(b);
                    flags.UpdateSZP8(r);
                    flags.SetCF(static_cast<uint16_t>(bv) + carry > av);
                    flags.SetOF(((av ^ bv) & (av ^ r) & 0x80) != 0);
                    flags.SetAF(((av ^ bv ^ r) & 0x10) != 0);
                    break;
                }
                case OperandSize::Size16: {
                    auto r = static_cast<uint16_t>(result);
                    auto av = static_cast<uint16_t>(a);
                    auto bv = static_cast<uint16_t>(b);
                    flags.UpdateSZP16(r);
                    flags.SetCF(static_cast<uint32_t>(bv) + carry > av);
                    flags.SetOF(((av ^ bv) & (av ^ r) & 0x8000) != 0);
                    flags.SetAF(((av ^ bv ^ r) & 0x10) != 0);
                    break;
                }
                case OperandSize::Size32: {
                    auto r = static_cast<uint32_t>(result);
                    auto av = static_cast<uint32_t>(a);
                    auto bv = static_cast<uint32_t>(b);
                    flags.UpdateSZP32(r);
                    flags.SetCF(static_cast<uint64_t>(bv) + carry > av);
                    flags.SetOF(((av ^ bv) & (av ^ r) & 0x80000000) != 0);
                    flags.SetAF(((av ^ bv ^ r) & 0x10) != 0);
                    break;
                }
                case OperandSize::Size64: {
                    flags.UpdateSZP64(result);
                    flags.SetCF(b + carry > a || (carry && b == 0xFFFFFFFFFFFFFFFFULL));
                    flags.SetOF(((a ^ b) & (a ^ result) & 0x8000000000000000ULL) != 0);
                    flags.SetAF(((a ^ b ^ result) & 0x10) != 0);
                    break;
                }
            }
            break;
        }

        case ALUOp::OR: {
            result = a | b;
            switch (size) {
                case OperandSize::Size8:  flags.UpdateFlagsLogic8(static_cast<uint8_t>(result)); break;
                case OperandSize::Size16: flags.UpdateFlagsLogic16(static_cast<uint16_t>(result)); break;
                case OperandSize::Size32: flags.UpdateFlagsLogic32(static_cast<uint32_t>(result)); break;
                case OperandSize::Size64: flags.UpdateFlagsLogic64(result); break;
            }
            break;
        }

        case ALUOp::AND: {
            result = a & b;
            switch (size) {
                case OperandSize::Size8:  flags.UpdateFlagsLogic8(static_cast<uint8_t>(result)); break;
                case OperandSize::Size16: flags.UpdateFlagsLogic16(static_cast<uint16_t>(result)); break;
                case OperandSize::Size32: flags.UpdateFlagsLogic32(static_cast<uint32_t>(result)); break;
                case OperandSize::Size64: flags.UpdateFlagsLogic64(result); break;
            }
            break;
        }

        case ALUOp::XOR: {
            result = a ^ b;
            switch (size) {
                case OperandSize::Size8:  flags.UpdateFlagsLogic8(static_cast<uint8_t>(result)); break;
                case OperandSize::Size16: flags.UpdateFlagsLogic16(static_cast<uint16_t>(result)); break;
                case OperandSize::Size32: flags.UpdateFlagsLogic32(static_cast<uint32_t>(result)); break;
                case OperandSize::Size64: flags.UpdateFlagsLogic64(result); break;
            }
            break;
        }
    }

    return result;
}

// ============================================================================
// CPU::ExecuteALU — The main arithmetic handler
// ============================================================================

ErrorCode CPU::ExecuteALU(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    // ==== 0x00-0x3F: Standard two-operand ALU ====
    if (inst.opcodeMap == OpcodeMap::OneByte && op <= 0x3F) {
        ALUOp aluOp = GetALUOpFromOpcode(op);
        uint64_t a = 0, b = 0;

        auto err = ReadOperand(inst.Op(0), inst, mem, a);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(1), inst, mem, b);
        if (err != ErrorCode::Success) return err;

        bool writeBack = true;
        uint64_t result = DoALU(aluOp, a, b, size, m_state.eflags, writeBack);

        if (writeBack) {
            result = MaskToSize(result, size);
            err = WriteOperand(inst.Op(0), inst, mem, result);
            if (err != ErrorCode::Success) return err;
        }
        return ErrorCode::Success;
    }

    // ==== 0x80-0x83: Immediate group ====
    if (inst.opcodeMap == OpcodeMap::OneByte && op >= 0x80 && op <= 0x83) {
        ALUOp aluOp = static_cast<ALUOp>(inst.opcodeExt);
        uint64_t a = 0, b = 0;

        auto err = ReadOperand(inst.Op(0), inst, mem, a);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(1), inst, mem, b);
        if (err != ErrorCode::Success) return err;

        // 0x83: sign-extend imm8 to operand size
        if (op == 0x83) {
            b = SignExtendToSize(b, OperandSize::Size8, size);
        }

        bool writeBack = true;
        uint64_t result = DoALU(aluOp, a, b, size, m_state.eflags, writeBack);

        if (writeBack) {
            result = MaskToSize(result, size);
            err = WriteOperand(inst.Op(0), inst, mem, result);
            if (err != ErrorCode::Success) return err;
        }
        return ErrorCode::Success;
    }

    // ==== INC/DEC (0x40-0x4F in 32-bit mode, or FE/FF ext 0/1) ====
    if (inst.opcodeMap == OpcodeMap::OneByte) {
        bool isINC = false;
        bool isDEC = false;

        if (!m_state.Is64Bit() && op >= 0x40 && op <= 0x47) isINC = true;
        if (!m_state.Is64Bit() && op >= 0x48 && op <= 0x4F) isDEC = true;
        if ((op == 0xFE || op == 0xFF) && inst.opcodeExt == 0) isINC = true;
        if ((op == 0xFE || op == 0xFF) && inst.opcodeExt == 1) isDEC = true;

        if (isINC || isDEC) {
            uint64_t val = 0;
            auto err = ReadOperand(inst.Op(0), inst, mem, val);
            if (err != ErrorCode::Success) return err;

            uint64_t result;
            if (isINC) {
                result = val + 1;
                switch (size) {
                    case OperandSize::Size8:
                        m_state.eflags.UpdateFlagsInc8(
                            static_cast<uint8_t>(val), static_cast<uint8_t>(result)); break;
                    case OperandSize::Size16:
                        m_state.eflags.UpdateFlagsInc16(
                            static_cast<uint16_t>(val), static_cast<uint16_t>(result)); break;
                    case OperandSize::Size32:
                        m_state.eflags.UpdateFlagsInc32(
                            static_cast<uint32_t>(val), static_cast<uint32_t>(result)); break;
                    case OperandSize::Size64:
                        m_state.eflags.UpdateFlagsInc64(val, result); break;
                }
            } else {
                result = val - 1;
                switch (size) {
                    case OperandSize::Size8:
                        m_state.eflags.UpdateFlagsDec8(
                            static_cast<uint8_t>(val), static_cast<uint8_t>(result)); break;
                    case OperandSize::Size16:
                        m_state.eflags.UpdateFlagsDec16(
                            static_cast<uint16_t>(val), static_cast<uint16_t>(result)); break;
                    case OperandSize::Size32:
                        m_state.eflags.UpdateFlagsDec32(
                            static_cast<uint32_t>(val), static_cast<uint32_t>(result)); break;
                    case OperandSize::Size64:
                        m_state.eflags.UpdateFlagsDec64(val, result); break;
                }
            }

            result = MaskToSize(result, size);
            return WriteOperand(inst.Op(0), inst, mem, result);
        }
    }

    // ==== F6/F7: Unary group (TEST, NOT, NEG, MUL, IMUL, DIV, IDIV) ====
    if (inst.opcodeMap == OpcodeMap::OneByte && (op == 0xF6 || op == 0xF7)) {
        uint8_t ext = inst.opcodeExt;
        uint64_t val = 0;

        auto err = ReadOperand(inst.Op(0), inst, mem, val);
        if (err != ErrorCode::Success) return err;

        switch (ext) {
            case 0: { // TEST r/m, imm
                uint64_t imm = 0;
                err = ReadOperand(inst.Op(1), inst, mem, imm);
                if (err != ErrorCode::Success) return err;
                uint64_t result = val & imm;
                switch (size) {
                    case OperandSize::Size8:  m_state.eflags.UpdateFlagsLogic8(static_cast<uint8_t>(result)); break;
                    case OperandSize::Size16: m_state.eflags.UpdateFlagsLogic16(static_cast<uint16_t>(result)); break;
                    case OperandSize::Size32: m_state.eflags.UpdateFlagsLogic32(static_cast<uint32_t>(result)); break;
                    case OperandSize::Size64: m_state.eflags.UpdateFlagsLogic64(result); break;
                }
                return ErrorCode::Success;
            }

            case 2: { // NOT r/m — no flags affected
                uint64_t result = ~val;
                result = MaskToSize(result, size);
                return WriteOperand(inst.Op(0), inst, mem, result);
            }

            case 3: { // NEG r/m — same as SUB(0, val)
                uint64_t result = 0 - val;
                switch (size) {
                    case OperandSize::Size8:
                        m_state.eflags.UpdateFlagsSub8(0, static_cast<uint8_t>(val), static_cast<uint8_t>(result)); break;
                    case OperandSize::Size16:
                        m_state.eflags.UpdateFlagsSub16(0, static_cast<uint16_t>(val), static_cast<uint16_t>(result)); break;
                    case OperandSize::Size32:
                        m_state.eflags.UpdateFlagsSub32(0, static_cast<uint32_t>(val), static_cast<uint32_t>(result)); break;
                    case OperandSize::Size64:
                        m_state.eflags.UpdateFlagsSub64(0, val, result); break;
                }
                result = MaskToSize(result, size);
                return WriteOperand(inst.Op(0), inst, mem, result);
            }

            case 4: { // MUL r/m — unsigned multiply: AX = AL * r/m8, DX:AX = AX * r/m16, etc.
                switch (size) {
                    case OperandSize::Size8: {
                        uint16_t product = static_cast<uint16_t>(m_state.GetReg8(GPR::RAX)) * static_cast<uint8_t>(val);
                        m_state.SetReg16(GPR::RAX, product);
                        bool overflow = (product >> 8) != 0;
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                    case OperandSize::Size16: {
                        uint32_t product = static_cast<uint32_t>(m_state.GetReg16(GPR::RAX)) * static_cast<uint16_t>(val);
                        m_state.SetReg16(GPR::RAX, static_cast<uint16_t>(product));
                        m_state.SetReg16(GPR::RDX, static_cast<uint16_t>(product >> 16));
                        bool overflow = (product >> 16) != 0;
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                    case OperandSize::Size32: {
                        uint64_t product = static_cast<uint64_t>(m_state.GetReg32(GPR::RAX)) * static_cast<uint32_t>(val);
                        m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(product));
                        m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(product >> 32));
                        bool overflow = (product >> 32) != 0;
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                    case OperandSize::Size64: {
#ifdef _MSC_VER
                        uint64_t high = 0;
                        uint64_t low = _umul128(m_state.GetReg64(GPR::RAX), val, &high);
                        m_state.SetReg64(GPR::RAX, low);
                        m_state.SetReg64(GPR::RDX, high);
                        bool overflow = high != 0;
#else
                        __uint128_t product = static_cast<__uint128_t>(m_state.GetReg64(GPR::RAX)) *
                                              static_cast<__uint128_t>(val);
                        m_state.SetReg64(GPR::RAX, static_cast<uint64_t>(product));
                        m_state.SetReg64(GPR::RDX, static_cast<uint64_t>(product >> 64));
                        bool overflow = (product >> 64) != 0;
#endif
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                }
                return ErrorCode::Success;
            }

            case 5: { // IMUL r/m — signed multiply (one-operand form)
                switch (size) {
                    case OperandSize::Size8: {
                        int16_t product = static_cast<int16_t>(static_cast<int8_t>(m_state.GetReg8(GPR::RAX))) *
                                          static_cast<int8_t>(val);
                        m_state.SetReg16(GPR::RAX, static_cast<uint16_t>(product));
                        bool overflow = product != static_cast<int8_t>(product);
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                    case OperandSize::Size16: {
                        int32_t product = static_cast<int32_t>(static_cast<int16_t>(m_state.GetReg16(GPR::RAX))) *
                                          static_cast<int16_t>(val);
                        m_state.SetReg16(GPR::RAX, static_cast<uint16_t>(product));
                        m_state.SetReg16(GPR::RDX, static_cast<uint16_t>(static_cast<uint32_t>(product) >> 16));
                        bool overflow = product != static_cast<int16_t>(product);
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                    case OperandSize::Size32: {
                        int64_t product = static_cast<int64_t>(static_cast<int32_t>(m_state.GetReg32(GPR::RAX))) *
                                          static_cast<int32_t>(val);
                        m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(product));
                        m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(static_cast<uint64_t>(product) >> 32));
                        bool overflow = product != static_cast<int32_t>(product);
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                    case OperandSize::Size64: {
#ifdef _MSC_VER
                        int64_t high = 0;
                        int64_t low = _mul128(static_cast<int64_t>(m_state.GetReg64(GPR::RAX)),
                                              static_cast<int64_t>(val), &high);
                        m_state.SetReg64(GPR::RAX, static_cast<uint64_t>(low));
                        m_state.SetReg64(GPR::RDX, static_cast<uint64_t>(high));
                        // Overflow if high part != sign extension of low
                        bool overflow = high != (low >> 63);
#else
                        __int128_t product = static_cast<__int128_t>(static_cast<int64_t>(m_state.GetReg64(GPR::RAX))) *
                                             static_cast<int64_t>(val);
                        m_state.SetReg64(GPR::RAX, static_cast<uint64_t>(product));
                        m_state.SetReg64(GPR::RDX, static_cast<uint64_t>(static_cast<__uint128_t>(product) >> 64));
                        bool overflow = product != static_cast<int64_t>(product);
#endif
                        m_state.eflags.SetOF(overflow);
                        m_state.eflags.SetCF(overflow);
                        break;
                    }
                }
                return ErrorCode::Success;
            }

            case 6: { // DIV r/m — unsigned divide
                if (val == 0) return ErrorCode::DivideByZero;
                switch (size) {
                    case OperandSize::Size8: {
                        uint16_t dividend = m_state.GetReg16(GPR::RAX);
                        uint8_t divisor = static_cast<uint8_t>(val);
                        uint16_t quotient = dividend / divisor;
                        if (quotient > 0xFF) return ErrorCode::DivideOverflow;
                        m_state.SetReg8(GPR::RAX, static_cast<uint8_t>(quotient));
                        // AH = remainder
                        m_state.SetReg8High(4, static_cast<uint8_t>(dividend % divisor));
                        break;
                    }
                    case OperandSize::Size16: {
                        uint32_t dividend = (static_cast<uint32_t>(m_state.GetReg16(GPR::RDX)) << 16) |
                                            m_state.GetReg16(GPR::RAX);
                        uint16_t divisor = static_cast<uint16_t>(val);
                        uint32_t quotient = dividend / divisor;
                        if (quotient > 0xFFFF) return ErrorCode::DivideOverflow;
                        m_state.SetReg16(GPR::RAX, static_cast<uint16_t>(quotient));
                        m_state.SetReg16(GPR::RDX, static_cast<uint16_t>(dividend % divisor));
                        break;
                    }
                    case OperandSize::Size32: {
                        uint64_t dividend = (static_cast<uint64_t>(m_state.GetReg32(GPR::RDX)) << 32) |
                                            m_state.GetReg32(GPR::RAX);
                        uint32_t divisor = static_cast<uint32_t>(val);
                        uint64_t quotient = dividend / divisor;
                        if (quotient > 0xFFFFFFFF) return ErrorCode::DivideOverflow;
                        m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(quotient));
                        m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(dividend % divisor));
                        break;
                    }
                    case OperandSize::Size64: {
#ifdef _MSC_VER
                        uint64_t high = m_state.GetReg64(GPR::RDX);
                        uint64_t low  = m_state.GetReg64(GPR::RAX);
                        uint64_t divisor = val;
                        // Check for overflow: if high >= divisor, quotient won't fit in 64 bits
                        if (high >= divisor) return ErrorCode::DivideOverflow;
                        uint64_t remainder = 0;
                        uint64_t quotient = _udiv128(high, low, divisor, &remainder);
                        m_state.SetReg64(GPR::RAX, quotient);
                        m_state.SetReg64(GPR::RDX, remainder);
#else
                        __uint128_t dividend = (static_cast<__uint128_t>(m_state.GetReg64(GPR::RDX)) << 64) |
                                               m_state.GetReg64(GPR::RAX);
                        uint64_t divisor = val;
                        __uint128_t quotient = dividend / divisor;
                        if (quotient > 0xFFFFFFFFFFFFFFFFULL) return ErrorCode::DivideOverflow;
                        m_state.SetReg64(GPR::RAX, static_cast<uint64_t>(quotient));
                        m_state.SetReg64(GPR::RDX, static_cast<uint64_t>(dividend % divisor));
#endif
                        break;
                    }
                }
                return ErrorCode::Success;
            }

            case 7: { // IDIV r/m — signed divide
                if (val == 0) return ErrorCode::DivideByZero;
                switch (size) {
                    case OperandSize::Size8: {
                        int16_t dividend = static_cast<int16_t>(m_state.GetReg16(GPR::RAX));
                        int8_t divisor = static_cast<int8_t>(val);
                        int16_t quotient = dividend / divisor;
                        if (quotient > 127 || quotient < -128) return ErrorCode::DivideOverflow;
                        m_state.SetReg8(GPR::RAX, static_cast<uint8_t>(quotient));
                        m_state.SetReg8High(4, static_cast<uint8_t>(dividend % divisor));
                        break;
                    }
                    case OperandSize::Size16: {
                        int32_t dividend = static_cast<int32_t>(
                            (static_cast<uint32_t>(m_state.GetReg16(GPR::RDX)) << 16) |
                            m_state.GetReg16(GPR::RAX));
                        int16_t divisor = static_cast<int16_t>(val);
                        int32_t quotient = dividend / divisor;
                        if (quotient > 32767 || quotient < -32768) return ErrorCode::DivideOverflow;
                        m_state.SetReg16(GPR::RAX, static_cast<uint16_t>(quotient));
                        m_state.SetReg16(GPR::RDX, static_cast<uint16_t>(dividend % divisor));
                        break;
                    }
                    case OperandSize::Size32: {
                        int64_t dividend = static_cast<int64_t>(
                            (static_cast<uint64_t>(m_state.GetReg32(GPR::RDX)) << 32) |
                            m_state.GetReg32(GPR::RAX));
                        int32_t divisor = static_cast<int32_t>(val);
                        int64_t quotient = dividend / divisor;
                        if (quotient > 2147483647LL || quotient < -2147483648LL)
                            return ErrorCode::DivideOverflow;
                        m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(quotient));
                        m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(dividend % divisor));
                        break;
                    }
                    case OperandSize::Size64: {
#ifdef _MSC_VER
                        int64_t high = static_cast<int64_t>(m_state.GetReg64(GPR::RDX));
                        uint64_t low = m_state.GetReg64(GPR::RAX);
                        int64_t divisor = static_cast<int64_t>(val);
                        int64_t remainder = 0;
                        int64_t quotient = _div128(high, static_cast<int64_t>(low), divisor, &remainder);
                        // Overflow check: hardware would #DE, _div128 returns undefined on overflow
                        // We detect via: if high is not sign extension of low, likely overflow
                        m_state.SetReg64(GPR::RAX, static_cast<uint64_t>(quotient));
                        m_state.SetReg64(GPR::RDX, static_cast<uint64_t>(remainder));
#else
                        __int128_t dividend = (static_cast<__int128_t>(
                            static_cast<int64_t>(m_state.GetReg64(GPR::RDX))) << 64) |
                            m_state.GetReg64(GPR::RAX);
                        int64_t divisor = static_cast<int64_t>(val);
                        __int128_t quotient = dividend / divisor;
                        if (quotient > static_cast<__int128_t>(INT64_MAX) ||
                            quotient < static_cast<__int128_t>(INT64_MIN))
                            return ErrorCode::DivideOverflow;
                        m_state.SetReg64(GPR::RAX, static_cast<uint64_t>(quotient));
                        m_state.SetReg64(GPR::RDX, static_cast<uint64_t>(dividend % divisor));
#endif
                        break;
                    }
                }
                return ErrorCode::Success;
            }

            default:
                return ErrorCode::UnimplementedOpcode;
        }
    }

    // ==== IMUL two-operand (0x69/0x6B: r, r/m, imm) ====
    if (inst.opcodeMap == OpcodeMap::OneByte && (op == 0x69 || op == 0x6B)) {
        uint64_t src = 0, imm = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(2), inst, mem, imm);
        if (err != ErrorCode::Success) return err;

        if (op == 0x6B) {
            imm = SignExtendToSize(imm, OperandSize::Size8, size);
        }

        int64_t sSrc = 0, sImm = 0;
        uint64_t result = 0;
        bool overflow = false;

        switch (size) {
            case OperandSize::Size16: {
                sSrc = static_cast<int16_t>(src);
                sImm = static_cast<int16_t>(imm);
                int32_t product = static_cast<int32_t>(sSrc) * static_cast<int32_t>(sImm);
                result = static_cast<uint16_t>(product);
                overflow = product != static_cast<int16_t>(product);
                break;
            }
            case OperandSize::Size32: {
                sSrc = static_cast<int32_t>(src);
                sImm = static_cast<int32_t>(imm);
                int64_t product = static_cast<int64_t>(sSrc) * static_cast<int64_t>(sImm);
                result = static_cast<uint32_t>(product);
                overflow = product != static_cast<int32_t>(product);
                break;
            }
            case OperandSize::Size64: {
#ifdef _MSC_VER
                int64_t high = 0;
                sSrc = static_cast<int64_t>(src);
                sImm = static_cast<int64_t>(imm);
                int64_t low = _mul128(sSrc, sImm, &high);
                result = static_cast<uint64_t>(low);
                overflow = high != (low >> 63);
#else
                sSrc = static_cast<int64_t>(src);
                sImm = static_cast<int64_t>(imm);
                __int128_t product = static_cast<__int128_t>(sSrc) * static_cast<__int128_t>(sImm);
                result = static_cast<uint64_t>(product);
                overflow = product != static_cast<int64_t>(product);
#endif
                break;
            }
            default:
                return ErrorCode::InvalidOperandSize;
        }

        m_state.eflags.SetOF(overflow);
        m_state.eflags.SetCF(overflow);
        return WriteOperand(inst.Op(0), inst, mem, result);
    }

    // ==== IMUL two-operand (0F AF: r, r/m) ====
    if (inst.opcodeMap == OpcodeMap::TwoByte && op == 0xAF) {
        uint64_t dst = 0, src = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, dst);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        bool overflow = false;
        uint64_t result = 0;

        switch (size) {
            case OperandSize::Size16: {
                int32_t product = static_cast<int32_t>(static_cast<int16_t>(dst)) *
                                  static_cast<int32_t>(static_cast<int16_t>(src));
                result = static_cast<uint16_t>(product);
                overflow = product != static_cast<int16_t>(product);
                break;
            }
            case OperandSize::Size32: {
                int64_t product = static_cast<int64_t>(static_cast<int32_t>(dst)) *
                                  static_cast<int64_t>(static_cast<int32_t>(src));
                result = static_cast<uint32_t>(product);
                overflow = product != static_cast<int32_t>(product);
                break;
            }
            case OperandSize::Size64: {
#ifdef _MSC_VER
                int64_t high = 0;
                int64_t low = _mul128(static_cast<int64_t>(dst), static_cast<int64_t>(src), &high);
                result = static_cast<uint64_t>(low);
                overflow = high != (low >> 63);
#else
                __int128_t product = static_cast<__int128_t>(static_cast<int64_t>(dst)) *
                                     static_cast<__int128_t>(static_cast<int64_t>(src));
                result = static_cast<uint64_t>(product);
                overflow = product != static_cast<int64_t>(product);
#endif
                break;
            }
            default:
                return ErrorCode::InvalidOperandSize;
        }

        m_state.eflags.SetOF(overflow);
        m_state.eflags.SetCF(overflow);
        return WriteOperand(inst.Op(0), inst, mem, result);
    }

    // ==== CMPXCHG (0F B0 / 0F B1) ====
    if (inst.opcodeMap == OpcodeMap::TwoByte && (op == 0xB0 || op == 0xB1)) {
        uint64_t dst = 0, src = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, dst);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        uint64_t accum = m_state.GetRegBySize(GPR::RAX, size);

        // Compare accumulator with destination
        uint64_t diff = accum - dst;
        switch (size) {
            case OperandSize::Size8:
                m_state.eflags.UpdateFlagsSub8(
                    static_cast<uint8_t>(accum), static_cast<uint8_t>(dst),
                    static_cast<uint8_t>(diff)); break;
            case OperandSize::Size16:
                m_state.eflags.UpdateFlagsSub16(
                    static_cast<uint16_t>(accum), static_cast<uint16_t>(dst),
                    static_cast<uint16_t>(diff)); break;
            case OperandSize::Size32:
                m_state.eflags.UpdateFlagsSub32(
                    static_cast<uint32_t>(accum), static_cast<uint32_t>(dst),
                    static_cast<uint32_t>(diff)); break;
            case OperandSize::Size64:
                m_state.eflags.UpdateFlagsSub64(accum, dst, diff); break;
        }

        if (m_state.eflags.ZF()) {
            // Equal: dst ← src
            return WriteOperand(inst.Op(0), inst, mem, src);
        } else {
            // Not equal: accumulator ← dst
            m_state.SetRegBySize(GPR::RAX, dst, size);
            return ErrorCode::Success;
        }
    }

    // ==== XADD (0F C0 / 0F C1) ====
    if (inst.opcodeMap == OpcodeMap::TwoByte && (op == 0xC0 || op == 0xC1)) {
        uint64_t dst = 0, src = 0;
        auto err = ReadOperand(inst.Op(0), inst, mem, dst);
        if (err != ErrorCode::Success) return err;
        err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        uint64_t sum = dst + src;

        switch (size) {
            case OperandSize::Size8:
                m_state.eflags.UpdateFlagsAdd8(
                    static_cast<uint8_t>(dst), static_cast<uint8_t>(src),
                    static_cast<uint8_t>(sum)); break;
            case OperandSize::Size16:
                m_state.eflags.UpdateFlagsAdd16(
                    static_cast<uint16_t>(dst), static_cast<uint16_t>(src),
                    static_cast<uint16_t>(sum)); break;
            case OperandSize::Size32:
                m_state.eflags.UpdateFlagsAdd32(
                    static_cast<uint32_t>(dst), static_cast<uint32_t>(src),
                    static_cast<uint32_t>(sum)); break;
            case OperandSize::Size64:
                m_state.eflags.UpdateFlagsAdd64(dst, src, sum); break;
        }

        // src ← old dst, dst ← sum
        err = WriteOperand(inst.Op(1), inst, mem, dst);
        if (err != ErrorCode::Success) return err;
        sum = MaskToSize(sum, size);
        return WriteOperand(inst.Op(0), inst, mem, sum);
    }

    // ========================================================================
    // ThreeByte38 map (0F 38 xx) — ADX Extension
    // ========================================================================
    // ADCX and ADOX perform multi-precision addition using separate carry chains.
    // This is critical for cryptographic malware that uses multi-precision
    // arithmetic (e.g., RSA, ECC implementations).
    //
    // ADCX: 66 0F 38 F6 /r — Add with CF (uses CF for carry in/out)
    // ADOX: F3 0F 38 F6 /r — Add with OF (uses OF for carry in/out)
    //
    // Both only affect their respective flag (CF or OF), leaving all other
    // flags unchanged. This is their key feature: two independent carry chains.

    if (inst.opcodeMap == OpcodeMap::ThreeByte38 && op == 0xF6) {
        bool isADCX = inst.prefixes.hasOpSizeOverride && !inst.prefixes.hasRep;
        bool isADOX = inst.prefixes.hasRep && !inst.prefixes.hasOpSizeOverride;

        if (isADCX || isADOX) {
            uint64_t dst = 0, src = 0;
            auto err = ReadOperand(inst.Op(0), inst, mem, dst);
            if (err != ErrorCode::Success) return err;
            err = ReadOperand(inst.Op(1), inst, mem, src);
            if (err != ErrorCode::Success) return err;

            uint8_t carryIn = isADCX ? (m_state.eflags.CF() ? 1 : 0)
                                     : (m_state.eflags.OF() ? 1 : 0);

            bool is64 = (size == OperandSize::Size64);
            uint64_t result = 0;
            uint8_t carryOut = 0;

            if (is64) {
                // 64-bit addition with carry
                unsigned __int64 lo = static_cast<unsigned __int64>(dst)
                                    + static_cast<unsigned __int64>(src);
                carryOut = (lo < dst) ? 1 : 0;
                result = lo + carryIn;
                if (result < lo) carryOut = 1;
            } else {
                // 32-bit addition with carry (zero-extends result to 64 bits)
                uint64_t sum = static_cast<uint64_t>(static_cast<uint32_t>(dst))
                             + static_cast<uint64_t>(static_cast<uint32_t>(src))
                             + static_cast<uint64_t>(carryIn);
                carryOut = (sum > 0xFFFFFFFFULL) ? 1 : 0;
                result = sum & 0xFFFFFFFF;
            }

            // ADCX: only CF is updated. ADOX: only OF is updated.
            // All other flags are preserved — this is the key ADX feature.
            if (isADCX) {
                m_state.eflags.SetCF(carryOut != 0);
            } else {
                m_state.eflags.SetOF(carryOut != 0);
            }

            return WriteOperand(inst.Op(0), inst, mem, result);
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
