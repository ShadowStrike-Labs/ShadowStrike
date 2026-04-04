/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "InstructionDecoder.hpp"
#include "../../Common/Constants.hpp"
#include <cstring>

namespace Phantom {

// ============================================================================
// Main Decode Entry Point
// ============================================================================

ErrorCode InstructionDecoder::Decode(
    std::span<const uint8_t> bytes,
    GuestAddress rip,
    CPUMode mode,
    DecodedInstruction& out) noexcept
{
    out.Clear();
    out.address = rip;

    if (bytes.empty()) {
        return ErrorCode::TruncatedInstruction;
    }

    uint32_t offset = 0;

    // Phase 1: Prefixes
    auto err = DecodePrefixes(bytes, mode, out.prefixes, offset);
    if (err != ErrorCode::Success) return err;

    // Phase 2: Opcode
    err = DecodeOpcode(bytes, offset, out.opcodeMap, out.opcode);
    if (err != ErrorCode::Success) return err;

    // Resolve effective operand and address sizes
    out.operandSize = out.prefixes.EffectiveOperandSize(mode);
    out.addressSize = out.prefixes.EffectiveAddressSize(mode);

    // Phase 3: ModR/M (if required)
    if (OpcodeRequiresModRM(out.opcodeMap, out.opcode)) {
        err = DecodeModRM(bytes, offset, mode, out.prefixes, out);
        if (err != ErrorCode::Success) return err;

        // Phase 4: SIB (if ModRM indicates it)
        if (out.hasModRM) {
            uint8_t mod = Encoding::ModRM_Mod(out.modrm);
            uint8_t rm  = Encoding::ModRM_RM(out.modrm);

            // SIB byte present when mod != 3 and rm == 4
            bool needSIB = (mod != Encoding::kMod_Register) &&
                           (rm == Encoding::kRM_SIB) &&
                           (out.addressSize != AddressSize::Addr16);

            if (needSIB) {
                err = DecodeSIB(bytes, offset, mode, out.prefixes, out);
                if (err != ErrorCode::Success) return err;
            }

            // Phase 5: Displacement
            uint8_t dispSize = 0;
            if (mod == Encoding::kMod_Disp8) {
                dispSize = 1;
            } else if (mod == Encoding::kMod_Disp32) {
                dispSize = (out.addressSize == AddressSize::Addr16) ? 2 : 4;
            } else if (mod == Encoding::kMod_Indirect) {
                if (out.addressSize == AddressSize::Addr16) {
                    // 16-bit: mod=0, rm=6 → disp16
                    if (rm == 6) dispSize = 2;
                } else {
                    // 32/64-bit: mod=0, rm=5 → disp32 (or RIP-relative in 64-bit)
                    if (rm == Encoding::kRM_Disp32) {
                        dispSize = 4;
                    }
                    // SIB with base=5, mod=0 → disp32
                    if (out.hasSIB && Encoding::SIB_Base(out.sib) == Encoding::kSIB_Disp32Base) {
                        dispSize = 4;
                    }
                }
            }

            if (dispSize > 0) {
                err = DecodeDisplacement(bytes, offset, dispSize, out);
                if (err != ErrorCode::Success) return err;
            }
        }
    }

    // Phase 6: Immediate
    uint8_t immSize = OpcodeImmediateSize(out.opcodeMap, out.opcode, out.operandSize);
    if (immSize > 0) {
        err = DecodeImmediate(bytes, offset, immSize, out);
        if (err != ErrorCode::Success) return err;
    }

    // Validate total length
    if (offset > Encoding::kMaxInstructionLength) {
        return ErrorCode::InstructionTooLong;
    }

    out.length = static_cast<uint8_t>(offset);
    return ErrorCode::Success;
}

// ============================================================================
// Phase 1: Prefix Decoding
// ============================================================================

ErrorCode InstructionDecoder::DecodePrefixes(
    std::span<const uint8_t> bytes,
    CPUMode mode,
    InstructionPrefixes& prefixes,
    uint32_t& offset) noexcept
{
    prefixes = InstructionPrefixes{};

    while (offset < bytes.size() && offset < Encoding::kMaxInstructionLength) {
        uint8_t b = bytes[offset];

        // In 64-bit mode, 0x40-0x4F are REX prefixes, not INC/DEC
        if (mode == CPUMode::Long64 && b >= Encoding::kREXBase && b <= Encoding::kREXMax) {
            prefixes.hasREX = true;
            prefixes.rexW = (b & Encoding::kREX_W) != 0;
            prefixes.rexR = (b & Encoding::kREX_R) != 0;
            prefixes.rexX = (b & Encoding::kREX_X) != 0;
            prefixes.rexB = (b & Encoding::kREX_B) != 0;
            prefixes.prefixCount++;
            offset++;
            // REX must be the last prefix — stop looking for more
            break;
        }

        switch (b) {
            // Group 1: Lock/Rep
            case Encoding::kPrefixLOCK:
                prefixes.hasLock = true;
                break;
            case Encoding::kPrefixREP:
                prefixes.hasRep = true;
                break;
            case Encoding::kPrefixREPNE:
                prefixes.hasRepNE = true;
                break;

            // Group 2: Segment overrides
            case Encoding::kPrefixCS:
                prefixes.hasSegOverride = true;
                prefixes.segOverride = SegReg::CS;
                break;
            case Encoding::kPrefixSS:
                prefixes.hasSegOverride = true;
                prefixes.segOverride = SegReg::SS;
                break;
            case Encoding::kPrefixDS:
                prefixes.hasSegOverride = true;
                prefixes.segOverride = SegReg::DS;
                break;
            case Encoding::kPrefixES:
                prefixes.hasSegOverride = true;
                prefixes.segOverride = SegReg::ES;
                break;
            case Encoding::kPrefixFS:
                prefixes.hasSegOverride = true;
                prefixes.segOverride = SegReg::FS;
                break;
            case Encoding::kPrefixGS:
                prefixes.hasSegOverride = true;
                prefixes.segOverride = SegReg::GS;
                break;

            // Group 3: Operand size override
            case Encoding::kPrefixOpSize:
                prefixes.hasOpSizeOverride = true;
                break;

            // Group 4: Address size override
            case Encoding::kPrefixAddrSize:
                prefixes.hasAddrSizeOverride = true;
                break;

            default:
                // Not a prefix — this is the opcode byte
                return ErrorCode::Success;
        }

        prefixes.prefixCount++;
        offset++;
    }

    return ErrorCode::Success;
}

// ============================================================================
// Phase 2: Opcode Decoding
// ============================================================================

ErrorCode InstructionDecoder::DecodeOpcode(
    std::span<const uint8_t> bytes,
    uint32_t& offset,
    OpcodeMap& map,
    uint8_t& opcode) noexcept
{
    if (offset >= bytes.size()) return ErrorCode::TruncatedInstruction;

    uint8_t b = bytes[offset++];

    if (b != Encoding::kTwoByteEscape) {
        // 1-byte opcode
        map = OpcodeMap::OneByte;
        opcode = b;
        return ErrorCode::Success;
    }

    // 0x0F escape — need at least one more byte
    if (offset >= bytes.size()) return ErrorCode::TruncatedInstruction;

    b = bytes[offset];

    if (b == Encoding::kThreeByteEscape38) {
        offset++;
        if (offset >= bytes.size()) return ErrorCode::TruncatedInstruction;
        map = OpcodeMap::ThreeByte38;
        opcode = bytes[offset++];
        return ErrorCode::Success;
    }

    if (b == Encoding::kThreeByteEscape3A) {
        offset++;
        if (offset >= bytes.size()) return ErrorCode::TruncatedInstruction;
        map = OpcodeMap::ThreeByte3A;
        opcode = bytes[offset++];
        return ErrorCode::Success;
    }

    // 2-byte opcode (0F xx)
    map = OpcodeMap::TwoByte;
    opcode = b;
    offset++;
    return ErrorCode::Success;
}

// ============================================================================
// Phase 3: ModR/M Decoding
// ============================================================================

ErrorCode InstructionDecoder::DecodeModRM(
    std::span<const uint8_t> bytes,
    uint32_t& offset,
    CPUMode mode,
    const InstructionPrefixes& prefixes,
    DecodedInstruction& inst) noexcept
{
    if (offset >= bytes.size()) return ErrorCode::TruncatedInstruction;

    inst.modrm = bytes[offset++];
    inst.hasModRM = true;

    // Extract ModRM.reg extension (used for group opcodes)
    inst.opcodeExt = Encoding::ModRM_Reg(inst.modrm);

    return ErrorCode::Success;
}

// ============================================================================
// Phase 4: SIB Decoding
// ============================================================================

ErrorCode InstructionDecoder::DecodeSIB(
    std::span<const uint8_t> bytes,
    uint32_t& offset,
    [[maybe_unused]] CPUMode mode,
    [[maybe_unused]] const InstructionPrefixes& prefixes,
    DecodedInstruction& inst) noexcept
{
    if (offset >= bytes.size()) return ErrorCode::TruncatedInstruction;

    inst.sib = bytes[offset++];
    inst.hasSIB = true;

    return ErrorCode::Success;
}

// ============================================================================
// Phase 5: Displacement Reading
// ============================================================================

ErrorCode InstructionDecoder::DecodeDisplacement(
    std::span<const uint8_t> bytes,
    uint32_t& offset,
    uint8_t dispSize,
    DecodedInstruction& inst) noexcept
{
    inst.dispSize = dispSize;

    switch (dispSize) {
        case 1: {
            uint8_t val;
            if (!ReadByte(bytes, offset, val)) return ErrorCode::TruncatedInstruction;
            inst.displacement = SignExtend8(val);
            offset += 1;
            break;
        }
        case 2: {
            uint16_t val;
            if (!ReadWord(bytes, offset, val)) return ErrorCode::TruncatedInstruction;
            inst.displacement = SignExtend16(val);
            offset += 2;
            break;
        }
        case 4: {
            uint32_t val;
            if (!ReadDword(bytes, offset, val)) return ErrorCode::TruncatedInstruction;
            inst.displacement = SignExtend32(val);
            offset += 4;
            break;
        }
        default:
            return ErrorCode::InvalidModRM;
    }

    return ErrorCode::Success;
}

// ============================================================================
// Phase 6: Immediate Reading
// ============================================================================

ErrorCode InstructionDecoder::DecodeImmediate(
    std::span<const uint8_t> bytes,
    uint32_t& offset,
    uint8_t immSize,
    DecodedInstruction& inst) noexcept
{
    inst.immSize = immSize;

    switch (immSize) {
        case 1: {
            uint8_t val;
            if (!ReadByte(bytes, offset, val)) return ErrorCode::TruncatedInstruction;
            inst.immediate = SignExtend8(val);
            offset += 1;
            break;
        }
        case 2: {
            uint16_t val;
            if (!ReadWord(bytes, offset, val)) return ErrorCode::TruncatedInstruction;
            inst.immediate = SignExtend16(val);
            offset += 2;
            break;
        }
        case 4: {
            uint32_t val;
            if (!ReadDword(bytes, offset, val)) return ErrorCode::TruncatedInstruction;
            inst.immediate = SignExtend32(val);
            offset += 4;
            break;
        }
        case 8: {
            uint64_t val;
            if (!ReadQword(bytes, offset, val)) return ErrorCode::TruncatedInstruction;
            inst.immediate = static_cast<int64_t>(val);
            offset += 8;
            break;
        }
        default:
            return ErrorCode::InvalidOpcode;
    }

    return ErrorCode::Success;
}

// ============================================================================
// Operand Builders
// ============================================================================

void InstructionDecoder::BuildRegOperand(
    DecodedOperand& op,
    RegType regType,
    uint8_t index,
    OperandSize size,
    bool isHighByte) noexcept
{
    op.type = OperandType::Register;
    op.size = size;
    op.reg.regType = regType;
    op.reg.regIndex = index;
    op.reg.isHighByte = isHighByte;
}

void InstructionDecoder::BuildMemOperand(
    DecodedOperand& op,
    const DecodedInstruction& inst,
    CPUMode mode,
    const InstructionPrefixes& prefixes) noexcept
{
    op.type = OperandType::Memory;
    op.mem.hasBase = false;
    op.mem.hasIndex = false;
    op.mem.baseReg = 0xFF;
    op.mem.indexReg = 0xFF;
    op.mem.scale = 1;
    op.mem.displacement = inst.displacement;
    op.mem.ripRelative = false;

    uint8_t mod = Encoding::ModRM_Mod(inst.modrm);
    uint8_t rm  = Encoding::ModRM_RM(inst.modrm);

    // Apply REX.B to r/m field
    if (prefixes.hasREX && prefixes.rexB) {
        rm |= 0x08;
    }

    if (mode == CPUMode::Long64 || mode == CPUMode::Protected32) {
        if (inst.hasSIB) {
            // SIB addressing
            uint8_t base  = Encoding::SIB_Base(inst.sib);
            uint8_t index = Encoding::SIB_Index(inst.sib);
            uint8_t scale = Encoding::SIB_Scale(inst.sib);

            // Apply REX extensions
            if (prefixes.hasREX) {
                if (prefixes.rexB) base |= 0x08;
                if (prefixes.rexX) index |= 0x08;
            }

            // Base register
            if (!(base == 5 && mod == Encoding::kMod_Indirect)) {
                op.mem.hasBase = true;
                op.mem.baseReg = base;
            }

            // Index register (index=4 means no index)
            if ((index & 0x07) != Encoding::kSIB_NoIndex) {
                op.mem.hasIndex = true;
                op.mem.indexReg = index;
                op.mem.scale = Encoding::kScaleFactors[scale];
            }
        } else {
            // No SIB
            if (mod == Encoding::kMod_Indirect && (rm & 0x07) == Encoding::kRM_Disp32) {
                // RIP-relative in 64-bit, disp32 in 32-bit
                if (mode == CPUMode::Long64) {
                    op.mem.ripRelative = true;
                }
                // displacement already decoded
            } else {
                op.mem.hasBase = true;
                op.mem.baseReg = rm;
            }
        }
    }

    // Determine segment
    if (prefixes.hasSegOverride) {
        op.mem.segment = prefixes.segOverride;
    } else {
        // Default: SS for RSP/RBP-based, DS for everything else
        if (op.mem.hasBase) {
            op.mem.segment = DefaultSegment(op.mem.baseReg);
        } else {
            op.mem.segment = SegReg::DS;
        }
    }
}

void InstructionDecoder::BuildImmOperand(
    DecodedOperand& op,
    int64_t value,
    OperandSize size,
    bool isSigned) noexcept
{
    op.type = OperandType::Immediate;
    op.size = size;
    op.imm.value = static_cast<uint64_t>(value);
    op.imm.isSigned = isSigned;
}

void InstructionDecoder::BuildRelOperand(
    DecodedOperand& op,
    int64_t offset,
    OperandSize size) noexcept
{
    op.type = OperandType::RelativeOffset;
    op.size = size;
    op.rel.offset = offset;
}

// ============================================================================
// Opcode Classification Tables
// ============================================================================

bool InstructionDecoder::OpcodeRequiresModRM(OpcodeMap map, uint8_t opcode) const noexcept {
    if (map == OpcodeMap::TwoByte || map == OpcodeMap::ThreeByte38 || map == OpcodeMap::ThreeByte3A) {
        // Almost all 2-byte and 3-byte opcodes require ModR/M
        // Exceptions: 0F 05 (SYSCALL), 0F 07 (SYSRET), 0F 0B (UD2),
        //             0F 30-37 (WRMSR etc), 0F A2 (CPUID), 0F 31 (RDTSC)
        switch (opcode) {
            case 0x05: case 0x06: case 0x07: case 0x08:
            case 0x09: case 0x0B: case 0x0E:
            case 0x30: case 0x31: case 0x32: case 0x33:
            case 0x34: case 0x35: case 0x36: case 0x37:
            case 0x77: case 0xA2:
                return (map == OpcodeMap::TwoByte) ? false : true;
            default:
                return true;
        }
    }

    // 1-byte opcode ModRM requirement table
    // Most ALU ops (00-3F), MOV variants, LEA, etc. require ModRM
    // Short-form ALU (04/0C/14/1C/24/2C/34/3C + imm), PUSH/POP, INC/DEC (40-4F),
    // Jcc short, RET, INT, etc. do NOT require ModRM

    // Group by range:
    if (opcode <= 0x3F) {
        // ALU ops: xx0-xx5 require ModRM for 0,1,2,3 but not 4,5 (accum+imm)
        uint8_t low3 = opcode & 0x07;
        return (low3 <= 3);
    }

    // 0x40-0x4F: INC/DEC (32-bit) or REX (64-bit) — no ModRM
    if (opcode >= 0x40 && opcode <= 0x4F) return false;

    // 0x50-0x5F: PUSH/POP reg — no ModRM
    if (opcode >= 0x50 && opcode <= 0x5F) return false;

    // 0x60-0x6F
    switch (opcode) {
        case 0x60: case 0x61: return false; // PUSHA/POPA
        case 0x62: return true;  // BOUND (32-bit) or EVEX (64-bit)
        case 0x63: return true;  // ARPL (32-bit) / MOVSXD (64-bit)
        case 0x68: return false; // PUSH imm32
        case 0x69: return true;  // IMUL r, r/m, imm32
        case 0x6A: return false; // PUSH imm8
        case 0x6B: return true;  // IMUL r, r/m, imm8
        case 0x6C: case 0x6D: case 0x6E: case 0x6F: return false; // INS/OUTS
    }

    // 0x70-0x7F: Jcc short — no ModRM
    if (opcode >= 0x70 && opcode <= 0x7F) return false;

    // 0x80-0x83: ALU group — ModRM
    if (opcode >= 0x80 && opcode <= 0x83) return true;

    // 0x84-0x8F
    switch (opcode) {
        case 0x84: case 0x85: return true; // TEST
        case 0x86: case 0x87: return true; // XCHG
        case 0x88: case 0x89: case 0x8A: case 0x8B: return true; // MOV
        case 0x8C: case 0x8D: case 0x8E: return true; // MOV seg, LEA, MOV seg
        case 0x8F: return true; // POP r/m
    }

    // 0x90-0x9F
    if (opcode >= 0x90 && opcode <= 0x97) return false; // NOP/XCHG eAX
    switch (opcode) {
        case 0x98: case 0x99: return false; // CBW/CWD
        case 0x9A: return false; // CALL FAR (not in 64-bit)
        case 0x9B: return false; // WAIT/FWAIT
        case 0x9C: case 0x9D: return false; // PUSHF/POPF
        case 0x9E: case 0x9F: return false; // SAHF/LAHF
    }

    // 0xA0-0xAF: MOV moffs, string ops — no ModRM
    if (opcode >= 0xA0 && opcode <= 0xAF) return false;

    // 0xB0-0xBF: MOV reg, imm — no ModRM
    if (opcode >= 0xB0 && opcode <= 0xBF) return false;

    // 0xC0-0xCF
    switch (opcode) {
        case 0xC0: case 0xC1: return true;  // Shift group
        case 0xC2: case 0xC3: return false;  // RET
        case 0xC4: case 0xC5: return true;   // LES/LDS or VEX
        case 0xC6: case 0xC7: return true;   // MOV r/m, imm
        case 0xC8: return false;              // ENTER
        case 0xC9: return false;              // LEAVE
        case 0xCA: case 0xCB: return false;   // RETF
        case 0xCC: return false;              // INT3
        case 0xCD: return false;              // INT imm8
        case 0xCE: return false;              // INTO
        case 0xCF: return false;              // IRET
    }

    // 0xD0-0xDF
    if (opcode >= 0xD0 && opcode <= 0xD3) return true; // Shift group
    switch (opcode) {
        case 0xD4: case 0xD5: return false;  // AAM/AAD
        case 0xD6: return false;              // SALC (undoc)
        case 0xD7: return false;              // XLAT
    }
    // 0xD8-0xDF: FPU opcodes — all require ModRM
    if (opcode >= 0xD8 && opcode <= 0xDF) return true;

    // 0xE0-0xEF: LOOP/Jcc/IN/OUT — no ModRM
    if (opcode >= 0xE0 && opcode <= 0xEF) return false;

    // 0xF0-0xFF
    switch (opcode) {
        case 0xF0: case 0xF1: return false;  // LOCK/INT1
        case 0xF2: case 0xF3: return false;  // REPNE/REP
        case 0xF4: return false;              // HLT
        case 0xF5: return false;              // CMC
        case 0xF6: case 0xF7: return true;   // Unary group (NOT/NEG/MUL/DIV/IDIV)
        case 0xF8: case 0xF9: return false;  // CLC/STC
        case 0xFA: case 0xFB: return false;  // CLI/STI
        case 0xFC: case 0xFD: return false;  // CLD/STD
        case 0xFE: case 0xFF: return true;   // INC/DEC/CALL/JMP group
    }

    return false;
}

uint8_t InstructionDecoder::OpcodeImmediateSize(
    OpcodeMap map,
    uint8_t opcode,
    OperandSize opSize) const noexcept
{
    if (map == OpcodeMap::ThreeByte3A) {
        // 0F 3A xx: most take 1-byte immediate
        return 1;
    }

    if (map == OpcodeMap::TwoByte) {
        // Most 2-byte opcodes don't have immediates
        // Exceptions: 0F 70 (PSHUFD imm8), 0F C2 (CMPPS imm8), etc.
        switch (opcode) {
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0xC2: case 0xC4: case 0xC5: case 0xC6:
            case 0xBA: // BT/BTS/BTR/BTC r/m, imm8
                return 1;
            default:
                return 0;
        }
    }

    // 1-byte opcode map
    uint8_t opSizeBytes = static_cast<uint8_t>(opSize);

    // ALU accum+imm forms (04,0C,14,1C,24,2C,34,3C for 8-bit; 05,0D,15,1D,25,2D,35,3D for full)
    if (opcode <= 0x3F) {
        uint8_t low3 = opcode & 0x07;
        if (low3 == 4) return 1;                            // AL, imm8
        if (low3 == 5) return (opSizeBytes == 8) ? 4 : opSizeBytes; // eAX, imm16/32
        return 0;
    }

    switch (opcode) {
        // PUSH imm
        case 0x68: return (opSizeBytes == 8) ? 4 : opSizeBytes;
        case 0x6A: return 1;

        // IMUL r, r/m, imm
        case 0x69: return (opSizeBytes == 8) ? 4 : opSizeBytes;
        case 0x6B: return 1;

        // Jcc short
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            return 1;

        // ALU group r/m, imm
        case 0x80: case 0x82: return 1;                     // r/m8, imm8
        case 0x81: return (opSizeBytes == 8) ? 4 : opSizeBytes; // r/m, imm16/32
        case 0x83: return 1;                                 // r/m, imm8 (sign-extended)

        // MOV r, imm (register in opcode)
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            return 1;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            // In 64-bit with REX.W, MOV r64, imm64 (10-byte encoding)
            return opSizeBytes;

        // Shift group imm
        case 0xC0: case 0xC1: return 1;

        // RET imm16
        case 0xC2: case 0xCA: return 2;

        // MOV r/m, imm
        case 0xC6: return 1;
        case 0xC7: return (opSizeBytes == 8) ? 4 : opSizeBytes;

        // ENTER imm16, imm8
        case 0xC8: return 3; // 2 + 1 (special: we handle this in executor)

        // INT imm8
        case 0xCD: return 1;

        // TEST AL/eAX, imm
        case 0xA8: return 1;
        case 0xA9: return (opSizeBytes == 8) ? 4 : opSizeBytes;

        // MOV moffs
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            // Address size determines moffs size
            return 0; // moffs is displacement, not immediate

        // Jcc / CALL / JMP rel
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: return 1; // LOOPcc, JCXZ
        case 0xE8: return 4; // CALL rel32
        case 0xE9: return 4; // JMP rel32
        case 0xEB: return 1; // JMP rel8

        // IN/OUT imm8
        case 0xE4: case 0xE5: case 0xE6: case 0xE7: return 1;

        // TEST/NOT/NEG/MUL/DIV group — F6 has imm8 for TEST only (ext=0)
        case 0xF6: return 0; // Handled specially: only TEST has immediate
        case 0xF7: return 0; // Same: only TEST has immediate

        default:
            return 0;
    }
}

SegReg InstructionDecoder::DefaultSegment(uint8_t baseReg) const noexcept {
    // RSP (4) and RBP (5) default to SS; everything else defaults to DS
    if ((baseReg & 0x07) == 4 || (baseReg & 0x07) == 5) {
        return SegReg::SS;
    }
    return SegReg::DS;
}

// ============================================================================
// Operand decode helpers
// ============================================================================

void InstructionDecoder::DecodeModRMOperands(
    DecodedInstruction& inst,
    OperandSize regSize,
    OperandSize rmSize,
    bool regIsDst) noexcept
{
    uint8_t reg = Encoding::ModRM_Reg(inst.modrm);
    uint8_t mod = Encoding::ModRM_Mod(inst.modrm);

    if (inst.prefixes.hasREX && inst.prefixes.rexR) {
        reg |= 0x08;
    }

    uint8_t dstIdx = regIsDst ? 0 : 1;
    uint8_t srcIdx = regIsDst ? 1 : 0;

    // Register operand (from ModRM.reg)
    BuildRegOperand(inst.operands[dstIdx], RegType::GPR, reg, regSize);

    // R/M operand
    if (mod == Encoding::kMod_Register) {
        // Register direct
        uint8_t rm = Encoding::ModRM_RM(inst.modrm);
        if (inst.prefixes.hasREX && inst.prefixes.rexB) rm |= 0x08;
        BuildRegOperand(inst.operands[srcIdx], RegType::GPR, rm, rmSize);
    } else {
        // Memory
        inst.operands[srcIdx].size = rmSize;
        BuildMemOperand(inst.operands[srcIdx], inst, inst.prefixes.EffectiveAddressSize(CPUMode::Long64) == AddressSize::Addr64 ? CPUMode::Long64 : CPUMode::Protected32, inst.prefixes);
    }

    inst.operandCount = 2;
}

void InstructionDecoder::DecodeAccumImm(
    DecodedInstruction& inst,
    OperandSize size) noexcept
{
    BuildRegOperand(inst.operands[0], RegType::GPR, 0, size); // AL/AX/EAX/RAX
    BuildImmOperand(inst.operands[1], inst.immediate, size, true);
    inst.operandCount = 2;
}

void InstructionDecoder::DecodeOpcodeReg(
    DecodedInstruction& inst,
    uint8_t opcode,
    OperandSize size,
    const InstructionPrefixes& prefixes) noexcept
{
    uint8_t reg = opcode & 0x07;
    if (prefixes.hasREX && prefixes.rexB) reg |= 0x08;
    BuildRegOperand(inst.operands[0], RegType::GPR, reg, size);
    inst.operandCount = 1;
}

// ============================================================================
// Raw byte reading with bounds checking
// ============================================================================

bool InstructionDecoder::ReadByte(
    std::span<const uint8_t> bytes, uint32_t offset, uint8_t& out) const noexcept
{
    if (offset >= bytes.size()) return false;
    out = bytes[offset];
    return true;
}

bool InstructionDecoder::ReadWord(
    std::span<const uint8_t> bytes, uint32_t offset, uint16_t& out) const noexcept
{
    if (offset + 1 >= bytes.size()) return false;
    std::memcpy(&out, &bytes[offset], 2);
    return true;
}

bool InstructionDecoder::ReadDword(
    std::span<const uint8_t> bytes, uint32_t offset, uint32_t& out) const noexcept
{
    if (offset + 3 >= bytes.size()) return false;
    std::memcpy(&out, &bytes[offset], 4);
    return true;
}

bool InstructionDecoder::ReadQword(
    std::span<const uint8_t> bytes, uint32_t offset, uint64_t& out) const noexcept
{
    if (offset + 7 >= bytes.size()) return false;
    std::memcpy(&out, &bytes[offset], 8);
    return true;
}

} // namespace Phantom
