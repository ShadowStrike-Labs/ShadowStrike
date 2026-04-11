/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * BitManip.cpp — BT, BTS, BTR, BTC, BSF, BSR, POPCNT, LZCNT, TZCNT
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "../../../Common/Platform.hpp"
#include <bit>

namespace Phantom {

ErrorCode CPU::ExecuteBitManip(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    uint8_t op = inst.opcode;
    OperandSize size = inst.operandSize;

    // ThreeByte38/3A VEX-encoded BMI1/BMI2 instructions
    if ((inst.opcodeMap == OpcodeMap::ThreeByte38 || inst.opcodeMap == OpcodeMap::ThreeByte3A)
        && inst.prefixes.hasVEX) {
        return ExecuteBMI(inst, mem);
    }

    if (inst.opcodeMap != OpcodeMap::TwoByte) return ErrorCode::UnimplementedOpcode;

    // === BSF (0F BC) — Bit Scan Forward ===
    if (op == 0xBC && !inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        src = MaskToSize(src, size);
        if (src == 0) {
            m_state.eflags.SetZF(true);
            // Destination is undefined; we leave it unchanged
            return ErrorCode::Success;
        }

        m_state.eflags.SetZF(false);
        uint32_t idx = 0;
        switch (size) {
            case OperandSize::Size16: idx = static_cast<uint32_t>(std::countr_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: idx = static_cast<uint32_t>(std::countr_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: idx = static_cast<uint32_t>(std::countr_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }
        return WriteOperand(inst.Op(0), inst, mem, idx);
    }

    // === TZCNT (F3 0F BC) — Trailing Zero Count ===
    if (op == 0xBC && inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        src = MaskToSize(src, size);
        uint32_t cnt = 0;
        switch (size) {
            case OperandSize::Size16: cnt = static_cast<uint32_t>(std::countr_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: cnt = static_cast<uint32_t>(std::countr_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: cnt = static_cast<uint32_t>(std::countr_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }

        m_state.eflags.SetCF(src == 0);
        m_state.eflags.SetZF(cnt == 0);
        return WriteOperand(inst.Op(0), inst, mem, cnt);
    }

    // === BSR (0F BD) — Bit Scan Reverse ===
    if (op == 0xBD && !inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        src = MaskToSize(src, size);
        if (src == 0) {
            m_state.eflags.SetZF(true);
            return ErrorCode::Success;
        }

        m_state.eflags.SetZF(false);
        uint32_t bits = static_cast<uint32_t>(size) * 8;
        uint32_t idx = bits - 1 - static_cast<uint32_t>(std::countl_zero(src));
        // Adjust for smaller sizes
        switch (size) {
            case OperandSize::Size16: idx = 15 - static_cast<uint32_t>(std::countl_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: idx = 31 - static_cast<uint32_t>(std::countl_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: idx = 63 - static_cast<uint32_t>(std::countl_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }
        return WriteOperand(inst.Op(0), inst, mem, idx);
    }

    // === LZCNT (F3 0F BD) — Leading Zero Count ===
    if (op == 0xBD && inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        uint32_t cnt = 0;
        switch (size) {
            case OperandSize::Size16: cnt = static_cast<uint32_t>(std::countl_zero(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: cnt = static_cast<uint32_t>(std::countl_zero(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: cnt = static_cast<uint32_t>(std::countl_zero(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }

        m_state.eflags.SetCF(src == 0);
        m_state.eflags.SetZF(cnt == 0);
        return WriteOperand(inst.Op(0), inst, mem, cnt);
    }

    // === POPCNT (F3 0F B8) ===
    if (op == 0xB8 && inst.prefixes.hasRep) {
        uint64_t src = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, src);
        if (err != ErrorCode::Success) return err;

        uint32_t cnt = 0;
        switch (size) {
            case OperandSize::Size16: cnt = static_cast<uint32_t>(std::popcount(static_cast<uint16_t>(src))); break;
            case OperandSize::Size32: cnt = static_cast<uint32_t>(std::popcount(static_cast<uint32_t>(src))); break;
            case OperandSize::Size64: cnt = static_cast<uint32_t>(std::popcount(static_cast<uint64_t>(src))); break;
            default: return ErrorCode::InvalidOperandSize;
        }

        // POPCNT: all flags cleared, ZF = (src == 0)
        m_state.eflags.SetCF(false);
        m_state.eflags.SetOF(false);
        m_state.eflags.SetSF(false);
        m_state.eflags.SetZF(src == 0);
        m_state.eflags.SetAF(false);
        m_state.eflags.SetPF(false);
        return WriteOperand(inst.Op(0), inst, mem, cnt);
    }

    // === BT/BTS/BTR/BTC — register form (0F A3, 0F AB, 0F B3, 0F BB) ===
    // === BT/BTS/BTR/BTC — immediate form (0F BA /4-7) ===

    // Determine operation type
    enum class BTOp { BT, BTS, BTR, BTC };
    BTOp btOp = BTOp::BT;
    bool isBTGroup = false;

    if (op == 0xA3) { btOp = BTOp::BT;  isBTGroup = true; }
    if (op == 0xAB) { btOp = BTOp::BTS; isBTGroup = true; }
    if (op == 0xB3) { btOp = BTOp::BTR; isBTGroup = true; }
    if (op == 0xBB) { btOp = BTOp::BTC; isBTGroup = true; }

    if (op == 0xBA) {
        isBTGroup = true;
        switch (inst.opcodeExt) {
            case 4: btOp = BTOp::BT;  break;
            case 5: btOp = BTOp::BTS; break;
            case 6: btOp = BTOp::BTR; break;
            case 7: btOp = BTOp::BTC; break;
            default: return ErrorCode::UnimplementedOpcode;
        }
    }

    if (isBTGroup) {
        uint64_t bitIdx = 0;
        auto err = ReadOperand(inst.Op(1), inst, mem, bitIdx);
        if (err != ErrorCode::Success) return err;

        uint8_t bits = static_cast<uint8_t>(size) * 8;

        if (inst.Op(0).IsMemory() && op != 0xBA) {
            // Memory operand with register bit index: bit index is NOT masked.
            // The full signed bit offset addresses into adjacent memory bytes.
            int64_t signedBitIdx = static_cast<int64_t>(bitIdx);
            if (bits == 16) signedBitIdx = static_cast<int16_t>(bitIdx);
            else if (bits == 32) signedBitIdx = static_cast<int32_t>(bitIdx);

            GuestAddress baseAddr = CalculateEffectiveAddress(inst.Op(0), inst);
            int64_t byteOffset = signedBitIdx >> 3;        // Divide by 8 (arithmetic shift)
            uint8_t bitInByte = static_cast<uint8_t>(signedBitIdx & 7);
            if (bitInByte < 0) { bitInByte += 8; byteOffset--; }

            GuestAddress effectiveAddr = baseAddr + static_cast<uint64_t>(byteOffset);
            uint8_t byte = 0;
            err = mem.Read(effectiveAddr, &byte, 1);
            if (err != ErrorCode::Success) return err;

            m_state.eflags.SetCF(((byte >> bitInByte) & 1) != 0);

            uint8_t mask = static_cast<uint8_t>(1 << bitInByte);
            switch (btOp) {
                case BTOp::BT:  return ErrorCode::Success;
                case BTOp::BTS: byte |= mask; break;
                case BTOp::BTR: byte &= ~mask; break;
                case BTOp::BTC: byte ^= mask; break;
            }

            return mem.Write(effectiveAddr, &byte, 1);
        } else {
            // Register operand or immediate form: bit index IS masked to operand size
            uint64_t val = 0;
            err = ReadOperand(inst.Op(0), inst, mem, val);
            if (err != ErrorCode::Success) return err;

            bitIdx &= (bits - 1);

            m_state.eflags.SetCF(((val >> bitIdx) & 1) != 0);

            uint64_t mask = 1ULL << bitIdx;
            switch (btOp) {
                case BTOp::BT:  return ErrorCode::Success;
                case BTOp::BTS: val |= mask; break;
                case BTOp::BTR: val &= ~mask; break;
                case BTOp::BTC: val ^= mask; break;
            }

            return WriteOperand(inst.Op(0), inst, mem, val);
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

// ============================================================================
// BMI1 / BMI2 — VEX-encoded bit manipulation (ThreeByte38, ThreeByte3A)
// ============================================================================
// These instructions are used by sophisticated malware for:
//   - Code obfuscation (PDEP/PEXT bit-scatter/gather)
//   - Fast hashing (RORX non-destructive rotate)
//   - Optimized crypto (MULX unsigned multiply without flags)
//   - Compiler-generated code from modern toolchains
//
// Anti-evasion: CPUID reports BMI1 (leaf 7 EBX bit 3) and BMI2 (bit 8).
// All instructions below must execute correctly or malware detects the sandbox.

ErrorCode CPU::ExecuteBMI(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (!inst.prefixes.hasVEX) return ErrorCode::UnimplementedOpcode;

    const uint8_t op   = inst.opcode;
    const uint8_t pp   = inst.prefixes.vexPP;
    const uint8_t ext  = inst.opcodeExt;
    const bool    is64 = inst.prefixes.vexW;
    const uint8_t bits = is64 ? 64 : 32;

    // VEX.vvvv: additional register operand (decoder stores 0-15 directly)
    const uint8_t vvvv = static_cast<uint8_t>(15 - inst.prefixes.vexVVVV);

    // Helper: read GPR source from operand or ModRM r/m
    auto ReadSrc = [&](uint8_t opIdx, uint64_t& val) -> ErrorCode {
        return ReadOperand(inst.Op(opIdx), inst, mem, val);
    };

    // Helper: mask result to 32 or 64 bits
    auto Mask = [&](uint64_t val) -> uint64_t {
        return is64 ? val : (val & 0xFFFFFFFFULL);
    };

    // ====================================================================
    // ThreeByte38 map — BMI1 + BMI2 instructions
    // ====================================================================

    if (inst.opcodeMap == OpcodeMap::ThreeByte38) {
        // === ANDN (VEX.NDS.LZ.0F38.W0/W1 F2) — BMI1 ===
        // dest = ~src1 & src2    (src1 = vvvv, src2 = r/m)
        if (op == 0xF2 && pp == 0) {
            uint64_t src1 = m_state.GetRegBySize(static_cast<GPR>(vvvv),
                                is64 ? OperandSize::Size64 : OperandSize::Size32);
            uint64_t src2 = 0;
            auto err = ReadSrc(1, src2);
            if (err != ErrorCode::Success) return err;

            uint64_t result = Mask(~src1 & src2);

            // ANDN updates SF, ZF based on result. OF=CF=0. AF undefined.
            m_state.eflags.SetSF((result >> (bits - 1)) & 1);
            m_state.eflags.SetZF(result == 0);
            m_state.eflags.SetOF(false);
            m_state.eflags.SetCF(false);

            return WriteOperand(inst.Op(0), inst, mem, result);
        }

        // === BLSI / BLSMSK / BLSR (VEX.NDD.LZ.0F38.W0/W1 F3) — BMI1 ===
        // These are group opcodes distinguished by ModRM.reg (/1, /2, /3)
        // NDD: VEX.vvvv = destination, ModRM.r/m = source
        if (op == 0xF3 && pp == 0) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);

            uint64_t result = 0;
            bool cf = false;

            switch (ext) {
                case 1: // BLSR: dest = src & (src - 1) — Reset lowest set bit
                    result = Mask(src & (src - 1));
                    cf = (src == 0); // CF=1 if source was 0
                    break;
                case 2: // BLSMSK: dest = src ^ (src - 1) — Mask up to lowest set bit
                    result = Mask(src ^ (src - 1));
                    cf = (src == 0);
                    break;
                case 3: // BLSI: dest = src & (-src) — Extract lowest set bit
                    result = Mask(src & (Mask(~src) + 1));
                    cf = (src != 0); // CF=1 if source was non-zero
                    break;
                default:
                    return ErrorCode::UnimplementedOpcode;
            }

            m_state.eflags.SetSF((result >> (bits - 1)) & 1);
            m_state.eflags.SetZF(result == 0);
            m_state.eflags.SetOF(false);
            m_state.eflags.SetCF(cf);

            // NDD: write to vvvv register
            m_state.SetRegBySize(static_cast<GPR>(vvvv), result,
                                 is64 ? OperandSize::Size64 : OperandSize::Size32);
            return ErrorCode::Success;
        }

        // === BZHI (VEX.NDS.LZ.0F38.W0/W1 F5, pp=0) — BMI2 ===
        // Zero High Bits: dest = src & ((1 << index) - 1)
        // index is in bits [7:0] of the register specified by VEX.vvvv
        if (op == 0xF5 && pp == 0) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);

            uint64_t idx = m_state.GetRegBySize(static_cast<GPR>(vvvv),
                                is64 ? OperandSize::Size64 : OperandSize::Size32);
            uint8_t n = static_cast<uint8_t>(idx & 0xFF);

            uint64_t result;
            bool cf;
            if (n >= bits) {
                result = src;
                cf = false;
            } else if (n == 0) {
                result = 0;
                cf = true;
            } else {
                uint64_t mask = (1ULL << n) - 1;
                result = Mask(src & mask);
                cf = true; // CF = 1 if n < operand size
            }

            m_state.eflags.SetSF((result >> (bits - 1)) & 1);
            m_state.eflags.SetZF(result == 0);
            m_state.eflags.SetOF(false);
            m_state.eflags.SetCF(cf);

            return WriteOperand(inst.Op(0), inst, mem, result);
        }

        // === PDEP (VEX.NDS.LZ.F2.0F38.W0/W1 F5, pp=3) — BMI2 ===
        // Parallel Bits Deposit: scatter contiguous low bits of src into
        // positions selected by mask (from vvvv)
        if (op == 0xF5 && pp == 3) {
            uint64_t src = 0, mask = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);
            mask = Mask(m_state.GetRegBySize(static_cast<GPR>(vvvv),
                            is64 ? OperandSize::Size64 : OperandSize::Size32));

            uint64_t result = 0;
            uint64_t k = 0; // Source bit index
            for (uint8_t i = 0; i < bits && mask != 0; ++i) {
                if (mask & 1) {
                    if (src & (1ULL << k)) result |= (1ULL << i);
                    ++k;
                }
                mask >>= 1;
            }

            // PDEP does not affect any flags
            return WriteOperand(inst.Op(0), inst, mem, Mask(result));
        }

        // === PEXT (VEX.NDS.LZ.F3.0F38.W0/W1 F5, pp=2) — BMI2 ===
        // Parallel Bits Extract: gather bits from src at positions selected
        // by mask and compress them to contiguous low bits
        if (op == 0xF5 && pp == 2) {
            uint64_t src = 0, mask = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);
            mask = Mask(m_state.GetRegBySize(static_cast<GPR>(vvvv),
                            is64 ? OperandSize::Size64 : OperandSize::Size32));

            uint64_t result = 0;
            uint64_t k = 0; // Destination bit index
            for (uint8_t i = 0; i < bits && mask != 0; ++i) {
                if (mask & 1) {
                    if (src & (1ULL << i)) result |= (1ULL << k);
                    ++k;
                }
                mask >>= 1;
            }

            // PEXT does not affect any flags
            return WriteOperand(inst.Op(0), inst, mem, Mask(result));
        }

        // === MULX (VEX.NDD.LZ.F2.0F38.W0/W1 F6, pp=3) — BMI2 ===
        // Unsigned multiply: EDX:EAX * src → vvvv:dst (32-bit)
        //                    RDX * src → vvvv:dst (64-bit)
        // Encoding: dst = ModRM.reg, hi = vvvv, src = r/m
        // Implicit source: EDX/RDX
        // Does NOT affect any flags (key feature)
        if (op == 0xF6 && pp == 3) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);

            uint64_t implicitSrc = Mask(m_state.GetReg64(GPR::RDX));

            if (is64) {
#ifdef _MSC_VER
                uint64_t hi = 0;
                uint64_t lo = _umul128(implicitSrc, src, &hi);
#else
                __uint128_t product = static_cast<__uint128_t>(implicitSrc) * src;
                uint64_t lo = static_cast<uint64_t>(product);
                uint64_t hi = static_cast<uint64_t>(product >> 64);
#endif
                // dst (ModRM.reg) gets low 64, vvvv gets high 64
                err = WriteOperand(inst.Op(0), inst, mem, lo);
                if (err != ErrorCode::Success) return err;
                m_state.SetReg64(static_cast<GPR>(vvvv), hi);
            } else {
                uint64_t product = static_cast<uint64_t>(static_cast<uint32_t>(implicitSrc))
                                 * static_cast<uint64_t>(static_cast<uint32_t>(src));
                uint32_t lo = static_cast<uint32_t>(product);
                uint32_t hi = static_cast<uint32_t>(product >> 32);
                err = WriteOperand(inst.Op(0), inst, mem, lo);
                if (err != ErrorCode::Success) return err;
                m_state.SetReg32(static_cast<GPR>(vvvv), hi);
            }
            return ErrorCode::Success;
        }

        // === BEXTR (VEX.NDS.LZ.0F38.W0/W1 F7, pp=0) — BMI1 ===
        // Bit Field Extract: extract bits [start+len-1 : start] from src
        // Control: vvvv register, bits[7:0]=start, bits[15:8]=length
        if (op == 0xF7 && pp == 0) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);

            uint64_t ctrl = m_state.GetRegBySize(static_cast<GPR>(vvvv),
                                is64 ? OperandSize::Size64 : OperandSize::Size32);
            uint8_t start  = static_cast<uint8_t>(ctrl & 0xFF);
            uint8_t length = static_cast<uint8_t>((ctrl >> 8) & 0xFF);

            uint64_t result;
            if (start >= bits) {
                result = 0;
            } else if (length == 0) {
                result = 0;
            } else {
                uint64_t mask = (length >= bits) ? ~0ULL : ((1ULL << length) - 1);
                result = Mask((src >> start) & mask);
            }

            m_state.eflags.SetZF(result == 0);
            m_state.eflags.SetCF(false);
            m_state.eflags.SetOF(false);
            // SF undefined per spec; we clear it for determinism
            m_state.eflags.SetSF(false);

            return WriteOperand(inst.Op(0), inst, mem, result);
        }

        // === SARX (VEX.NDS.LZ.F3.0F38.W0/W1 F7, pp=2) — BMI2 ===
        // Arithmetic right shift without affecting flags
        if (op == 0xF7 && pp == 2) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;

            uint64_t count = m_state.GetRegBySize(static_cast<GPR>(vvvv),
                                is64 ? OperandSize::Size64 : OperandSize::Size32);
            uint8_t shift = static_cast<uint8_t>(count & (bits - 1));

            uint64_t result;
            if (is64) {
                result = static_cast<uint64_t>(
                    static_cast<int64_t>(src) >> shift);
            } else {
                result = static_cast<uint64_t>(static_cast<uint32_t>(
                    static_cast<int32_t>(static_cast<uint32_t>(src)) >> shift));
            }

            return WriteOperand(inst.Op(0), inst, mem, result);
        }

        // === SHLX (VEX.NDS.LZ.66.0F38.W0/W1 F7, pp=1) — BMI2 ===
        // Logical left shift without affecting flags
        if (op == 0xF7 && pp == 1) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;

            uint64_t count = m_state.GetRegBySize(static_cast<GPR>(vvvv),
                                is64 ? OperandSize::Size64 : OperandSize::Size32);
            uint8_t shift = static_cast<uint8_t>(count & (bits - 1));

            uint64_t result = Mask(Mask(src) << shift);
            return WriteOperand(inst.Op(0), inst, mem, result);
        }

        // === SHRX (VEX.NDS.LZ.F2.0F38.W0/W1 F7, pp=3) — BMI2 ===
        // Logical right shift without affecting flags
        if (op == 0xF7 && pp == 3) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);

            uint64_t count = m_state.GetRegBySize(static_cast<GPR>(vvvv),
                                is64 ? OperandSize::Size64 : OperandSize::Size32);
            uint8_t shift = static_cast<uint8_t>(count & (bits - 1));

            uint64_t result = src >> shift;
            return WriteOperand(inst.Op(0), inst, mem, result);
        }
    }

    // ====================================================================
    // ThreeByte3A map — RORX (BMI2)
    // ====================================================================

    if (inst.opcodeMap == OpcodeMap::ThreeByte3A) {
        // === RORX (VEX.LZ.F2.0F3A.W0/W1 F0, pp=3) — BMI2 ===
        // Rotate right by immediate without affecting flags.
        // Commonly used in SHA-256 implementations and obfuscated code.
        if (op == 0xF0 && pp == 3) {
            uint64_t src = 0;
            auto err = ReadSrc(1, src);
            if (err != ErrorCode::Success) return err;
            src = Mask(src);

            uint8_t imm = static_cast<uint8_t>(inst.immediate & 0xFF);
            uint8_t rot = imm & (bits - 1);

            uint64_t result;
            if (rot == 0) {
                result = src;
            } else if (is64) {
                result = (src >> rot) | (src << (64 - rot));
            } else {
                uint32_t s = static_cast<uint32_t>(src);
                result = static_cast<uint64_t>((s >> rot) | (s << (32 - rot)));
            }

            return WriteOperand(inst.Op(0), inst, mem, result);
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
