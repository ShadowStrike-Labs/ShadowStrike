/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FPUOps.cpp — Basic x87 FPU operations used by malware
 *              FLD, FST, FSTP, FADD, FSUB, FMUL, FDIV, FILD, FIST,
 *              FINIT, FLDZ, FLD1, FXCH, FCOMPP, FTST, FABS, FCHS
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include <cmath>

namespace Phantom {

ErrorCode CPU::ExecuteFPU(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (inst.opcodeMap != OpcodeMap::OneByte) return ErrorCode::UnimplementedOpcode;

    uint8_t op = inst.opcode;      // D8-DF
    uint8_t modrm = inst.modrm;
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t ext = inst.opcodeExt;   // ModRM.reg (3 bits)
    uint8_t rm  = modrm & 7;

    // === D9 opcodes ===
    if (op == 0xD9) {
        if (mod != 3) {
            // Memory operands
            switch (ext) {
                case 0: { // FLD m32fp
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    float val = 0;
                    auto err = mem.Read(addr, &val, 4);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPush(static_cast<long double>(val));
                    return ErrorCode::Success;
                }
                case 2: { // FST m32fp
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    float val = static_cast<float>(m_state.FPU_ST(0).value);
                    return mem.Write(addr, &val, 4);
                }
                case 3: { // FSTP m32fp
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    float val = static_cast<float>(m_state.FPU_ST(0).value);
                    auto err = mem.Write(addr, &val, 4);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPop();
                    return ErrorCode::Success;
                }
                case 5: { // FLDCW m16
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    return mem.Read(addr, &m_state.fpuControl, 2);
                }
                case 7: { // FNSTCW m16
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    return mem.Write(addr, &m_state.fpuControl, 2);
                }
                default: return ErrorCode::UnimplementedOpcode;
            }
        } else {
            // Register operands (mod=3)
            if (modrm >= 0xC0 && modrm <= 0xC7) {
                // FLD ST(i) — push ST(i) onto stack
                long double val = m_state.FPU_ST(rm).value;
                m_state.FPUPush(val);
                return ErrorCode::Success;
            }
            if (modrm >= 0xC8 && modrm <= 0xCF) {
                // FXCH ST(i)
                long double temp = m_state.FPU_ST(0).value;
                m_state.FPU_ST(0).value = m_state.FPU_ST(rm).value;
                m_state.FPU_ST(rm).value = temp;
                return ErrorCode::Success;
            }
            switch (modrm) {
                case 0xE0: // FCHS: ST(0) = -ST(0)
                    m_state.FPU_ST(0).value = -m_state.FPU_ST(0).value;
                    return ErrorCode::Success;
                case 0xE1: // FABS: ST(0) = |ST(0)|
                    m_state.FPU_ST(0).value = std::fabsl(m_state.FPU_ST(0).value);
                    return ErrorCode::Success;
                case 0xE4: // FTST: compare ST(0) with 0.0
                    if (m_state.FPU_ST(0).value == 0.0L) {
                        m_state.fpuStatus = (m_state.fpuStatus & ~0x4500) | 0x4000; // C3=1, C0=C2=0 → equal
                    } else if (m_state.FPU_ST(0).value > 0.0L) {
                        m_state.fpuStatus = (m_state.fpuStatus & ~0x4500); // C3=C0=C2=0 → greater
                    } else {
                        m_state.fpuStatus = (m_state.fpuStatus & ~0x4500) | 0x0100; // C0=1 → less
                    }
                    return ErrorCode::Success;
                case 0xE8: // FLD1: push 1.0
                    m_state.FPUPush(1.0L);
                    return ErrorCode::Success;
                case 0xEE: // FLDZ: push 0.0
                    m_state.FPUPush(0.0L);
                    return ErrorCode::Success;
                default: return ErrorCode::UnimplementedOpcode;
            }
        }
    }

    // === D8 opcodes (FADD/FMUL/FCOM/FCOMP/FSUB/FSUBR/FDIV/FDIVR m32fp or ST) ===
    if (op == 0xD8) {
        long double a = m_state.FPU_ST(0).value;
        long double b = 0;

        if (mod != 3) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            float fval = 0;
            auto err = mem.Read(addr, &fval, 4);
            if (err != ErrorCode::Success) return err;
            b = static_cast<long double>(fval);
        } else {
            b = m_state.FPU_ST(rm).value;
        }

        switch (ext) {
            case 0: m_state.FPU_ST(0).value = a + b; return ErrorCode::Success; // FADD
            case 1: m_state.FPU_ST(0).value = a * b; return ErrorCode::Success; // FMUL
            case 4: m_state.FPU_ST(0).value = a - b; return ErrorCode::Success; // FSUB
            case 5: m_state.FPU_ST(0).value = b - a; return ErrorCode::Success; // FSUBR
            case 6: {
                if (b == 0.0L) return ErrorCode::DivideByZero;
                m_state.FPU_ST(0).value = a / b;
                return ErrorCode::Success; // FDIV
            }
            case 7: {
                if (a == 0.0L) return ErrorCode::DivideByZero;
                m_state.FPU_ST(0).value = b / a;
                return ErrorCode::Success; // FDIVR
            }
            case 2: // FCOM
            case 3: { // FCOMP
                if (a > b)       m_state.fpuStatus = (m_state.fpuStatus & ~0x4500);
                else if (a < b)  m_state.fpuStatus = (m_state.fpuStatus & ~0x4500) | 0x0100;
                else             m_state.fpuStatus = (m_state.fpuStatus & ~0x4500) | 0x4000;
                if (ext == 3) m_state.FPUPop();
                return ErrorCode::Success;
            }
            default: return ErrorCode::UnimplementedOpcode;
        }
    }

    // === DD opcodes (FLD m64fp, FST/FSTP m64fp, FUCOM, etc.) ===
    if (op == 0xDD) {
        if (mod != 3) {
            switch (ext) {
                case 0: { // FLD m64fp
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    double val = 0;
                    auto err = mem.Read(addr, &val, 8);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPush(static_cast<long double>(val));
                    return ErrorCode::Success;
                }
                case 2: { // FST m64fp
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    double val = static_cast<double>(m_state.FPU_ST(0).value);
                    return mem.Write(addr, &val, 8);
                }
                case 3: { // FSTP m64fp
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    double val = static_cast<double>(m_state.FPU_ST(0).value);
                    auto err = mem.Write(addr, &val, 8);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPop();
                    return ErrorCode::Success;
                }
                default: return ErrorCode::UnimplementedOpcode;
            }
        } else {
            // FFREE ST(i), etc
            if (modrm >= 0xC0 && modrm <= 0xC7) {
                // FFREE ST(i)
                m_state.fpuTag |= (3 << (((m_state.fpuTop + rm) & 7) * 2));
                return ErrorCode::Success;
            }
            if (modrm >= 0xD0 && modrm <= 0xD7) {
                // FST ST(i)
                m_state.FPU_ST(rm).value = m_state.FPU_ST(0).value;
                return ErrorCode::Success;
            }
            if (modrm >= 0xD8 && modrm <= 0xDF) {
                // FSTP ST(i)
                m_state.FPU_ST(rm).value = m_state.FPU_ST(0).value;
                m_state.FPUPop();
                return ErrorCode::Success;
            }
            return ErrorCode::UnimplementedOpcode;
        }
    }

    // === DB opcodes (FILD m32int, FIST m32int, etc.) ===
    if (op == 0xDB) {
        if (mod != 3) {
            switch (ext) {
                case 0: { // FILD m32int
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    int32_t val = 0;
                    auto err = mem.Read(addr, &val, 4);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPush(static_cast<long double>(val));
                    return ErrorCode::Success;
                }
                case 2: { // FIST m32int
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    int32_t val = static_cast<int32_t>(m_state.FPU_ST(0).value);
                    return mem.Write(addr, &val, 4);
                }
                case 3: { // FISTP m32int
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    int32_t val = static_cast<int32_t>(m_state.FPU_ST(0).value);
                    auto err = mem.Write(addr, &val, 4);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPop();
                    return ErrorCode::Success;
                }
                default: return ErrorCode::UnimplementedOpcode;
            }
        } else {
            if (modrm == 0xE3) {
                // FINIT / FNINIT
                m_state.fpuControl = 0x037F;
                m_state.fpuStatus = 0;
                m_state.fpuTag = 0xFFFF;
                m_state.fpuTop = 0;
                return ErrorCode::Success;
            }
            return ErrorCode::UnimplementedOpcode;
        }
    }

    // === DE opcodes (FCOMPP, FADDP, FMULP, etc.) ===
    if (op == 0xDE) {
        if (mod == 3) {
            if (modrm == 0xD9) {
                // FCOMPP: compare ST(0), ST(1) and pop both
                long double a = m_state.FPU_ST(0).value;
                long double b = m_state.FPU_ST(1).value;
                if (a > b)       m_state.fpuStatus = (m_state.fpuStatus & ~0x4500);
                else if (a < b)  m_state.fpuStatus = (m_state.fpuStatus & ~0x4500) | 0x0100;
                else             m_state.fpuStatus = (m_state.fpuStatus & ~0x4500) | 0x4000;
                m_state.FPUPop();
                m_state.FPUPop();
                return ErrorCode::Success;
            }

            long double a = m_state.FPU_ST(0).value;
            switch (ext) {
                case 0: m_state.FPU_ST(rm).value += a; break; // FADDP ST(i), ST(0)
                case 1: m_state.FPU_ST(rm).value *= a; break; // FMULP
                case 4: m_state.FPU_ST(rm).value -= a; break; // FSUBRP (reversed)
                case 5: m_state.FPU_ST(rm).value = a - m_state.FPU_ST(rm).value; break; // FSUBP
                case 6: {
                    if (a == 0.0L) return ErrorCode::DivideByZero;
                    m_state.FPU_ST(rm).value /= a; break; // FDIVRP
                }
                case 7: {
                    long double stI = m_state.FPU_ST(rm).value;
                    if (stI == 0.0L) return ErrorCode::DivideByZero;
                    m_state.FPU_ST(rm).value = a / stI; break; // FDIVP
                }
                default: return ErrorCode::UnimplementedOpcode;
            }
            m_state.FPUPop();
            return ErrorCode::Success;
        }
        return ErrorCode::UnimplementedOpcode;
    }

    // === DF opcodes (FILD m16int, FILD m64int, FNSTSW AX) ===
    if (op == 0xDF) {
        if (mod != 3) {
            switch (ext) {
                case 0: { // FILD m16int
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    int16_t val = 0;
                    auto err = mem.Read(addr, &val, 2);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPush(static_cast<long double>(val));
                    return ErrorCode::Success;
                }
                case 5: { // FILD m64int
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    int64_t val = 0;
                    auto err = mem.Read(addr, &val, 8);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPush(static_cast<long double>(val));
                    return ErrorCode::Success;
                }
                case 7: { // FISTP m64int
                    GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
                    int64_t val = static_cast<int64_t>(m_state.FPU_ST(0).value);
                    auto err = mem.Write(addr, &val, 8);
                    if (err != ErrorCode::Success) return err;
                    m_state.FPUPop();
                    return ErrorCode::Success;
                }
                default: return ErrorCode::UnimplementedOpcode;
            }
        } else {
            if (modrm == 0xE0) {
                // FNSTSW AX
                m_state.SetReg16(GPR::RAX, m_state.fpuStatus);
                return ErrorCode::Success;
            }
            return ErrorCode::UnimplementedOpcode;
        }
    }

    // === DA/DC opcodes — basic handling for common forms ===
    if (op == 0xDC) {
        long double a = m_state.FPU_ST(0).value;
        long double b = 0;

        if (mod != 3) {
            GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);
            double dval = 0;
            auto err = mem.Read(addr, &dval, 8);
            if (err != ErrorCode::Success) return err;
            b = static_cast<long double>(dval);
        } else {
            b = m_state.FPU_ST(rm).value;
        }

        switch (ext) {
            case 0: m_state.FPU_ST(mod == 3 ? rm : 0).value = a + b; return ErrorCode::Success;
            case 1: m_state.FPU_ST(mod == 3 ? rm : 0).value = a * b; return ErrorCode::Success;
            case 4: m_state.FPU_ST(mod == 3 ? rm : 0).value = a - b; return ErrorCode::Success;
            case 5: m_state.FPU_ST(mod == 3 ? rm : 0).value = b - a; return ErrorCode::Success;
            case 6: {
                if (b == 0.0L) return ErrorCode::DivideByZero;
                m_state.FPU_ST(mod == 3 ? rm : 0).value = a / b;
                return ErrorCode::Success;
            }
            case 7: {
                if (a == 0.0L) return ErrorCode::DivideByZero;
                m_state.FPU_ST(mod == 3 ? rm : 0).value = b / a;
                return ErrorCode::Success;
            }
            default: return ErrorCode::UnimplementedOpcode;
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
