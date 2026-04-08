/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "Decoder.hpp"

#include <cstring>

namespace Phantom::Disasm {

// ============================================================================
// Local encoding constants
// ============================================================================

namespace {

constexpr uint8_t kPrefixLOCK     = 0xF0;
constexpr uint8_t kPrefixREPNE    = 0xF2;
constexpr uint8_t kPrefixREP      = 0xF3;
constexpr uint8_t kPrefixCS       = 0x2E;
constexpr uint8_t kPrefixSS       = 0x36;
constexpr uint8_t kPrefixDS       = 0x3E;
constexpr uint8_t kPrefixES       = 0x26;
constexpr uint8_t kPrefixFS       = 0x64;
constexpr uint8_t kPrefixGS       = 0x65;
constexpr uint8_t kPrefixOpSize   = 0x66;
constexpr uint8_t kPrefixAddrSize = 0x67;

constexpr uint8_t kREXBase = 0x40;
constexpr uint8_t kREXMax  = 0x4F;
constexpr uint8_t kREX_W   = 0x08;
constexpr uint8_t kREX_R   = 0x04;
constexpr uint8_t kREX_X   = 0x02;
constexpr uint8_t kREX_B   = 0x01;

constexpr uint8_t kVEX2Byte = 0xC5;
constexpr uint8_t kVEX3Byte = 0xC4;
constexpr uint8_t kTwoByteEscape  = 0x0F;
constexpr uint8_t kThreeByteEsc38 = 0x38;
constexpr uint8_t kThreeByteEsc3A = 0x3A;

constexpr uint8_t ModRM_Mod(uint8_t b) { return (b >> 6) & 0x03; }
constexpr uint8_t ModRM_Reg(uint8_t b) { return (b >> 3) & 0x07; }
constexpr uint8_t ModRM_RM(uint8_t b)  { return b & 0x07; }
constexpr uint8_t SIB_Scale(uint8_t b) { return (b >> 6) & 0x03; }
constexpr uint8_t SIB_Index(uint8_t b) { return (b >> 3) & 0x07; }
constexpr uint8_t SIB_Base(uint8_t b)  { return b & 0x07; }

constexpr uint8_t kMod_Indirect   = 0;
constexpr uint8_t kMod_Disp8      = 1;
constexpr uint8_t kMod_Disp32     = 2;
constexpr uint8_t kMod_Register   = 3;
constexpr uint8_t kRM_SIB         = 4;
constexpr uint8_t kRM_Disp32      = 5;
constexpr uint8_t kSIB_NoIndex    = 4;
constexpr uint8_t kSIB_Disp32Base = 5;
constexpr uint8_t kScaleFactors[4] = { 1, 2, 4, 8 };

// Forward declaration — defined below after ResolveMnemonic
Mnemonic ResolveFPUMnemonicImpl(uint8_t primaryOp, uint8_t modrm) noexcept;

} // anonymous namespace

// ============================================================================
// DecodeContext::Reset
// ============================================================================

void Decoder::DecodeContext::Reset() noexcept {
    buffer = nullptr;  bufferLength = 0;  offset = 0;  rip = 0;
    hasLock = false;  hasRep = false;  hasRepNE = false;
    hasSegOverride = false;  segOverride = Register::NONE;
    hasOpSizeOverride = false;  hasAddrSizeOverride = false;
    hasREX = false;  rexW = rexR = rexX = rexB = false;
    hasVEX = false;  vexL = 0;  vexPP = 0;  vexMMMMM = 1;  vexVVVV = 0;  vexW = false;
    hasEVEX = false;  evexZ = 0;  evexLL = 0;  evexB = 0;
    evexAAA = 0;  evexV2 = 0;  evexR2 = 0;
    prefixCount = 0;
    opcodeMap = 0;  opcode = 0;  opcodeExt = 0;
    modrm = 0;  sib = 0;  hasModRM = false;  hasSIB = false;
    effectiveOperandWidth = 32;  effectiveAddressWidth = 64;
}

// ============================================================================
// Bounds-checked byte reading
// ============================================================================

bool Decoder::ReadByte(const DecodeContext& ctx, uint32_t off, uint8_t& out) const noexcept {
    if (off >= ctx.bufferLength) return false;
    out = ctx.buffer[off];
    return true;
}

bool Decoder::ReadWord(const DecodeContext& ctx, uint32_t off, uint16_t& out) const noexcept {
    if (off + 1 >= ctx.bufferLength) return false;
    std::memcpy(&out, ctx.buffer + off, 2);
    return true;
}

bool Decoder::ReadDword(const DecodeContext& ctx, uint32_t off, uint32_t& out) const noexcept {
    if (off + 3 >= ctx.bufferLength) return false;
    std::memcpy(&out, ctx.buffer + off, 4);
    return true;
}

bool Decoder::ReadQword(const DecodeContext& ctx, uint32_t off, uint64_t& out) const noexcept {
    if (off + 7 >= ctx.bufferLength) return false;
    std::memcpy(&out, ctx.buffer + off, 8);
    return true;
}

// ============================================================================
// Sign extension
// ============================================================================

int64_t Decoder::SignExtend8(uint8_t v) noexcept {
    return static_cast<int64_t>(static_cast<int8_t>(v));
}
int64_t Decoder::SignExtend16(uint16_t v) noexcept {
    return static_cast<int64_t>(static_cast<int16_t>(v));
}
int64_t Decoder::SignExtend32(uint32_t v) noexcept {
    return static_cast<int64_t>(static_cast<int32_t>(v));
}

// ============================================================================
// Init
// ============================================================================

Status Decoder::Init(MachineMode mode) noexcept {
    m_mode = mode;
    m_initialized = true;
    return Status::Success;
}

// ============================================================================
// ResolveEffectiveSizes
// ============================================================================

void Decoder::ResolveEffectiveSizes(DecodeContext& ctx) noexcept {
    switch (m_mode) {
    case MachineMode::Long64:
        if (ctx.rexW || ctx.vexW)
            ctx.effectiveOperandWidth = 64;
        else if (ctx.hasOpSizeOverride && !ctx.hasVEX && !ctx.hasEVEX)
            ctx.effectiveOperandWidth = 16;
        else
            ctx.effectiveOperandWidth = 32;
        ctx.effectiveAddressWidth = ctx.hasAddrSizeOverride ? 32 : 64;
        break;
    case MachineMode::LongCompat32:
    case MachineMode::Legacy32:
        ctx.effectiveOperandWidth = ctx.hasOpSizeOverride ? 16 : 32;
        ctx.effectiveAddressWidth = ctx.hasAddrSizeOverride ? 16 : 32;
        break;
    case MachineMode::Real16:
        ctx.effectiveOperandWidth = ctx.hasOpSizeOverride ? 32 : 16;
        ctx.effectiveAddressWidth = ctx.hasAddrSizeOverride ? 32 : 16;
        break;
    }
}

// ============================================================================
// DecodeFull - main decode pipeline
// ============================================================================

Status Decoder::DecodeFull(
    const uint8_t* buffer, size_t length,
    DecodedInstruction& instruction, DecodedOperand* operands) noexcept
{
    if (!buffer || length == 0) return Status::InvalidInput;
    if (!m_initialized) return Status::InternalError;

    instruction.Clear();
    for (uint8_t i = 0; i < MAX_OPERANDS; ++i) operands[i] = DecodedOperand{};

    DecodeContext ctx;
    ctx.Reset();
    ctx.buffer = buffer;
    ctx.bufferLength = length;

    // Phase 1: Legacy prefixes + REX
    Status st = DecodePrefixes(ctx);
    if (st != Status::Success) return st;

    // Phase 1b: VEX
    if (ctx.offset < ctx.bufferLength) {
        uint8_t b = ctx.buffer[ctx.offset];
        if (b == kVEX2Byte || b == kVEX3Byte) {
            st = DecodeVEX(ctx);
            if (st != Status::Success) return st;
            if (ctx.hasVEX) {
                if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
                ctx.opcode = ctx.buffer[ctx.offset++];
                switch (ctx.vexMMMMM) {
                    case 1: ctx.opcodeMap = 1; break;
                    case 2: ctx.opcodeMap = 2; break;
                    case 3: ctx.opcodeMap = 3; break;
                    default: return Status::InvalidPrefix;
                }
                goto vex_done;
            }
        }
    }

    // Phase 1c: EVEX
    if (ctx.offset < ctx.bufferLength && ctx.buffer[ctx.offset] == 0x62) {
        st = DecodeEVEX(ctx);
        if (st != Status::Success) return st;
        if (ctx.hasEVEX) {
            if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
            ctx.opcode = ctx.buffer[ctx.offset++];
            switch (ctx.vexMMMMM) {
                case 1: ctx.opcodeMap = 1; break;
                case 2: ctx.opcodeMap = 2; break;
                case 3: ctx.opcodeMap = 3; break;
                default: return Status::InvalidPrefix;
            }
            goto vex_done;
        }
    }

    // Phase 2: Opcode
    st = DecodeOpcode(ctx);
    if (st != Status::Success) return st;

vex_done:
    ResolveEffectiveSizes(ctx);

    // Phase 3: ModR/M
    if (OpcodeRequiresModRM(ctx.opcodeMap, ctx.opcode)) {
        st = DecodeModRM(ctx);
        if (st != Status::Success) return st;

        if (ctx.hasModRM) {
            uint8_t mod = ModRM_Mod(ctx.modrm);
            uint8_t rm  = ModRM_RM(ctx.modrm);

            // Phase 4: SIB
            if (mod != kMod_Register && rm == kRM_SIB && ctx.effectiveAddressWidth != 16) {
                st = DecodeSIB(ctx);
                if (st != Status::Success) return st;
            }

            // Phase 5: Displacement
            uint8_t dispSize = 0;
            if (mod == kMod_Disp8) {
                dispSize = 1;
            } else if (mod == kMod_Disp32) {
                dispSize = (ctx.effectiveAddressWidth == 16) ? 2 : 4;
            } else if (mod == kMod_Indirect) {
                if (ctx.effectiveAddressWidth == 16) {
                    if (rm == 6) dispSize = 2;
                } else {
                    if (rm == kRM_Disp32) dispSize = 4;
                    if (ctx.hasSIB && SIB_Base(ctx.sib) == kSIB_Disp32Base) dispSize = 4;
                }
            }
            if (dispSize > 0) {
                int64_t disp = 0;
                st = DecodeDisplacement(ctx, dispSize, disp);
                if (st != Status::Success) return st;
            }
        }
    }

    // Phase 6: Immediate
    uint8_t immSize = 0;
    if (ctx.opcodeMap == 0 && ctx.opcode >= 0xA0 && ctx.opcode <= 0xA3) {
        immSize = (ctx.effectiveAddressWidth == 64) ? 8 :
                  (ctx.effectiveAddressWidth == 32) ? 4 : 2;
    } else if (ctx.opcodeMap == 0 && ctx.opcode == 0xF6 && ctx.hasModRM &&
               (ctx.opcodeExt == 0 || ctx.opcodeExt == 1)) {
        immSize = 1;
    } else if (ctx.opcodeMap == 0 && ctx.opcode == 0xF7 && ctx.hasModRM &&
               (ctx.opcodeExt == 0 || ctx.opcodeExt == 1)) {
        immSize = (ctx.effectiveOperandWidth == 16) ? 2 : 4;
    } else if (ctx.opcodeMap == 1 && ctx.opcode >= 0x80 && ctx.opcode <= 0x8F) {
        immSize = (ctx.effectiveOperandWidth == 16) ? 2 : 4;
    } else if (ctx.opcodeMap == 1 && (ctx.opcode == 0xA4 || ctx.opcode == 0xAC)) {
        immSize = 1;
    } else {
        immSize = OpcodeImmediateSize(ctx.opcodeMap, ctx.opcode, ctx.effectiveOperandWidth);
    }

    int64_t immediate = 0;
    if (immSize > 0) {
        st = DecodeImmediate(ctx, immSize, immediate);
        if (st != Status::Success) return st;
    }

    if (ctx.offset > MAX_INSTRUCTION_LENGTH) return Status::InstructionTooLong;

    // --- Populate instruction ---
    instruction.length = static_cast<uint8_t>(ctx.offset);
    instruction.opcode_map = ctx.opcodeMap;
    instruction.opcode = ctx.opcode;
    instruction.opcode_ext = ctx.opcodeExt;
    instruction.modrm = ctx.modrm;
    instruction.sib = ctx.sib;
    instruction.has_modrm = ctx.hasModRM;
    instruction.has_sib = ctx.hasSIB;
    instruction.operand_width = ctx.effectiveOperandWidth;
    instruction.address_width = ctx.effectiveAddressWidth;

    uint8_t copyLen = instruction.length < MAX_INSTRUCTION_LENGTH ? instruction.length : MAX_INSTRUCTION_LENGTH;
    std::memcpy(instruction.raw_bytes.data(), buffer, copyLen);

    if (ctx.hasLock)             instruction.attributes |= ATTRIB_HAS_LOCK;
    if (ctx.hasRep)              instruction.attributes |= ATTRIB_HAS_REP;
    if (ctx.hasRepNE)            instruction.attributes |= ATTRIB_HAS_REPNE;
    if (ctx.hasSegOverride)      instruction.attributes |= ATTRIB_HAS_SEGMENT_OVERRIDE;
    if (ctx.hasOpSizeOverride)   instruction.attributes |= ATTRIB_HAS_OPERAND_SIZE;
    if (ctx.hasAddrSizeOverride) instruction.attributes |= ATTRIB_HAS_ADDRESS_SIZE;
    if (ctx.hasREX)              instruction.attributes |= ATTRIB_HAS_REX;
    if (ctx.hasVEX)              instruction.attributes |= ATTRIB_HAS_VEX;
    if (ctx.hasEVEX)             instruction.attributes |= ATTRIB_HAS_EVEX;
    if (ctx.hasModRM)            instruction.attributes |= ATTRIB_HAS_MODRM;
    if (ctx.hasSIB)              instruction.attributes |= ATTRIB_HAS_SIB;
    if (ctx.hasSegOverride)      instruction.segment_override = ctx.segOverride;

    if (ctx.hasVEX) {
        instruction.encoding.has_vex = true;
        instruction.encoding.vex_l = ctx.vexL;
        instruction.encoding.vex_pp = ctx.vexPP;
        instruction.encoding.vex_vvvv = ctx.vexVVVV;
        instruction.encoding.vex_w = ctx.vexW;
    }
    if (ctx.hasEVEX) {
        instruction.encoding.has_evex = true;
        instruction.encoding.vex_l = ctx.vexL;
        instruction.encoding.vex_pp = ctx.vexPP;
        instruction.encoding.vex_vvvv = ctx.vexVVVV;
        instruction.encoding.vex_w = ctx.vexW;
        instruction.encoding.evex_z = ctx.evexZ;
        instruction.encoding.evex_ll = ctx.evexLL;
        instruction.encoding.evex_b = ctx.evexB;
        instruction.encoding.evex_aaa = ctx.evexAAA;
    }

    instruction.mnemonic = ResolveMnemonic(ctx);
    instruction.category = ResolveCategory(instruction.mnemonic);
    instruction.isa_ext = ResolveISAExtension(ctx);

    // --- Operand building ---
    if (ctx.opcodeMap == 0) {
        uint8_t op = ctx.opcode;
        // ALU r/m,reg / reg,r/m (00-3D)
        if (op <= 0x3D) {
            uint8_t low3 = op & 0x07;
            if (low3 <= 3 && ctx.hasModRM) {
                bool isWord = (low3 & 1) != 0;
                bool regIsDst = (low3 >= 2);
                uint16_t sz = isWord ? ctx.effectiveOperandWidth : 8;
                DecodeModRMOperands(ctx, instruction, operands, sz, sz, regIsDst);
            } else if (low3 == 4) {
                DecodeAccumImm(ctx, instruction, operands, 8);
                operands[1].imm.value.s = immediate;
                operands[1].imm.value.u = static_cast<uint64_t>(immediate);
            } else if (low3 == 5) {
                DecodeAccumImm(ctx, instruction, operands, ctx.effectiveOperandWidth);
                operands[1].imm.value.s = immediate;
                operands[1].imm.value.u = static_cast<uint64_t>(immediate);
            }
        }
        // PUSH/POP reg (50-5F)
        else if (op >= 0x50 && op <= 0x5F) {
            uint16_t sz = (m_mode == MachineMode::Long64) ? 64 : ctx.effectiveOperandWidth;
            DecodeOpcodeReg(ctx, instruction, operands, sz);
        }
        // Jcc short (70-7F)
        else if (op >= 0x70 && op <= 0x7F) {
            BuildImmOperand(operands[0], immediate, 8, true, true);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
            instruction.attributes |= ATTRIB_IS_RELATIVE;
        }
        // Group 1 (80-83)
        else if (op >= 0x80 && op <= 0x83 && ctx.hasModRM) {
            bool byte_op = (op == 0x80 || op == 0x82);
            uint16_t rmSz = byte_op ? 8 : ctx.effectiveOperandWidth;
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                uint8_t rm = ModRM_RM(ctx.modrm);
                if (ctx.rexB) rm |= 0x08;
                BuildRegOperand(operands[0], ResolveGPR(rm, rmSz, ctx.hasREX), rmSz);
            } else {
                BuildMemOperand(operands[0], ctx, 0, rmSz);
            }
            uint16_t immBits = (op == 0x83) ? 8 : rmSz;
            BuildImmOperand(operands[1], immediate, immBits, true);
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // TEST/XCHG/MOV (84-8B)
        else if (op >= 0x84 && op <= 0x8B && ctx.hasModRM) {
            bool isWord = (op & 1) != 0;
            bool regIsDst = (op >= 0x8A) || (op == 0x86 || op == 0x87);
            uint16_t sz = isWord ? ctx.effectiveOperandWidth : 8;
            DecodeModRMOperands(ctx, instruction, operands, sz, sz, regIsDst);
        }
        // MOV Sreg (8C, 8E), LEA (8D)
        else if ((op == 0x8C || op == 0x8D || op == 0x8E) && ctx.hasModRM) {
            uint16_t sz = ctx.effectiveOperandWidth;
            DecodeModRMOperands(ctx, instruction, operands, sz, sz, (op != 0x8C));
        }
        // POP r/m (8F)
        else if (op == 0x8F && ctx.hasModRM) {
            uint16_t sz = (m_mode == MachineMode::Long64) ? 64 : ctx.effectiveOperandWidth;
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                uint8_t rm = ModRM_RM(ctx.modrm);
                if (ctx.rexB) rm |= 0x08;
                BuildRegOperand(operands[0], ResolveGPR(rm, sz, ctx.hasREX), sz);
            } else {
                BuildMemOperand(operands[0], ctx, 0, sz);
            }
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
        }
        // NOP/XCHG eAX (90-97)
        else if (op >= 0x90 && op <= 0x97) {
            if (op == 0x90 && !ctx.hasREX) {
                instruction.operand_count = 0;
            } else {
                uint16_t sz = ctx.effectiveOperandWidth;
                BuildRegOperand(operands[0], ResolveGPR(0, sz, ctx.hasREX), sz);
                uint8_t r2 = op & 0x07;
                if (ctx.rexB) r2 |= 0x08;
                BuildRegOperand(operands[1], ResolveGPR(r2, sz, ctx.hasREX), sz);
                instruction.operand_count = 2;
                instruction.operand_count_visible = 2;
            }
        }
        // TEST AL/eAX, imm (A8-A9)
        else if (op == 0xA8 || op == 0xA9) {
            uint16_t sz = (op == 0xA8) ? 8 : ctx.effectiveOperandWidth;
            DecodeAccumImm(ctx, instruction, operands, sz);
            operands[1].imm.value.s = immediate;
            operands[1].imm.value.u = static_cast<uint64_t>(immediate);
        }
        // MOV reg8, imm8 (B0-B7)
        else if (op >= 0xB0 && op <= 0xB7) {
            uint8_t reg = op & 0x07;
            if (ctx.rexB) reg |= 0x08;
            BuildRegOperand(operands[0], ResolveGPR(reg, 8, ctx.hasREX), 8);
            BuildImmOperand(operands[1], immediate, 8, false);
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // MOV reg, imm (B8-BF)
        else if (op >= 0xB8 && op <= 0xBF) {
            uint16_t sz = ctx.effectiveOperandWidth;
            uint8_t reg = op & 0x07;
            if (ctx.rexB) reg |= 0x08;
            BuildRegOperand(operands[0], ResolveGPR(reg, sz, ctx.hasREX), sz);
            BuildImmOperand(operands[1], immediate, sz, false);
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // Shift group (C0,C1,D0-D3)
        else if ((op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3)) && ctx.hasModRM) {
            bool byte_op = (op == 0xC0 || op == 0xD0 || op == 0xD2);
            uint16_t sz = byte_op ? 8 : ctx.effectiveOperandWidth;
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                uint8_t rm = ModRM_RM(ctx.modrm); if (ctx.rexB) rm |= 0x08;
                BuildRegOperand(operands[0], ResolveGPR(rm, sz, ctx.hasREX), sz);
            } else {
                BuildMemOperand(operands[0], ctx, 0, sz);
            }
            if (op == 0xC0 || op == 0xC1)
                BuildImmOperand(operands[1], immediate, 8, false);
            else if (op == 0xD0 || op == 0xD1)
                BuildImmOperand(operands[1], 1, 8, false);
            else
                BuildRegOperand(operands[1], Register::CL, 8);
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // RET imm16 (C2), RETF imm16 (CA)
        else if (op == 0xC2 || op == 0xCA) {
            BuildImmOperand(operands[0], immediate, 16, false);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
        }
        // MOV r/m, imm (C6,C7)
        else if ((op == 0xC6 || op == 0xC7) && ctx.hasModRM) {
            uint16_t sz = (op == 0xC6) ? 8 : ctx.effectiveOperandWidth;
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                uint8_t rm = ModRM_RM(ctx.modrm); if (ctx.rexB) rm |= 0x08;
                BuildRegOperand(operands[0], ResolveGPR(rm, sz, ctx.hasREX), sz);
            } else {
                BuildMemOperand(operands[0], ctx, 0, sz);
            }
            BuildImmOperand(operands[1], immediate, sz, false);
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // ENTER (C8)
        else if (op == 0xC8) {
            BuildImmOperand(operands[0], immediate & 0xFFFF, 16, false);
            BuildImmOperand(operands[1], (immediate >> 16) & 0xFF, 8, false);
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // INT imm8 (CD)
        else if (op == 0xCD) {
            BuildImmOperand(operands[0], immediate, 8, false);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
        }
        // Group 3: F6/F7
        else if ((op == 0xF6 || op == 0xF7) && ctx.hasModRM) {
            uint16_t sz = (op == 0xF6) ? 8 : ctx.effectiveOperandWidth;
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                uint8_t rm = ModRM_RM(ctx.modrm); if (ctx.rexB) rm |= 0x08;
                BuildRegOperand(operands[0], ResolveGPR(rm, sz, ctx.hasREX), sz);
            } else {
                BuildMemOperand(operands[0], ctx, 0, sz);
            }
            if (ctx.opcodeExt <= 1) {
                BuildImmOperand(operands[1], immediate, sz, false);
                instruction.operand_count = 2;
            } else {
                instruction.operand_count = 1;
            }
            instruction.operand_count_visible = instruction.operand_count;
        }
        // Group 4/5: FE/FF
        else if ((op == 0xFE || op == 0xFF) && ctx.hasModRM) {
            uint16_t sz = (op == 0xFE) ? 8 : ctx.effectiveOperandWidth;
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                uint8_t rm = ModRM_RM(ctx.modrm); if (ctx.rexB) rm |= 0x08;
                BuildRegOperand(operands[0], ResolveGPR(rm, sz, ctx.hasREX), sz);
            } else {
                BuildMemOperand(operands[0], ctx, 0, sz);
            }
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
        }
        // CALL/JMP rel (E8,E9,EB)
        else if (op == 0xE8 || op == 0xE9 || op == 0xEB) {
            uint16_t sz = (op == 0xEB) ? 8 : ((ctx.effectiveOperandWidth == 16) ? 16 : 32);
            BuildImmOperand(operands[0], immediate, sz, true, true);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
            instruction.attributes |= ATTRIB_IS_RELATIVE;
        }
        // LOOPcc/JCXZ (E0-E3)
        else if (op >= 0xE0 && op <= 0xE3) {
            BuildImmOperand(operands[0], immediate, 8, true, true);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
            instruction.attributes |= ATTRIB_IS_RELATIVE;
        }
        // IN/OUT imm8 (E4-E7)
        else if (op >= 0xE4 && op <= 0xE7) {
            bool isIn = (op <= 0xE5);
            bool byte_op = !(op & 1);
            uint16_t sz = byte_op ? 8 : ctx.effectiveOperandWidth;
            if (isIn) {
                BuildRegOperand(operands[0], ResolveGPR(0, sz, ctx.hasREX), sz);
                BuildImmOperand(operands[1], immediate, 8, false);
            } else {
                BuildImmOperand(operands[0], immediate, 8, false);
                BuildRegOperand(operands[1], ResolveGPR(0, sz, ctx.hasREX), sz);
            }
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // IN/OUT DX (EC-EF)
        else if (op >= 0xEC && op <= 0xEF) {
            bool isIn = (op <= 0xED);
            bool byte_op = !(op & 1);
            uint16_t sz = byte_op ? 8 : ctx.effectiveOperandWidth;
            if (isIn) {
                BuildRegOperand(operands[0], ResolveGPR(0, sz, ctx.hasREX), sz);
                BuildRegOperand(operands[1], Register::DX, 16);
            } else {
                BuildRegOperand(operands[0], Register::DX, 16);
                BuildRegOperand(operands[1], ResolveGPR(0, sz, ctx.hasREX), sz);
            }
            instruction.operand_count = 2;
            instruction.operand_count_visible = 2;
        }
        // PUSH imm (68,6A)
        else if (op == 0x68 || op == 0x6A) {
            uint16_t sz = (op == 0x6A) ? 8 : ctx.effectiveOperandWidth;
            BuildImmOperand(operands[0], immediate, sz, true);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
        }
        // IMUL r,r/m,imm (69,6B)
        else if ((op == 0x69 || op == 0x6B) && ctx.hasModRM) {
            uint16_t sz = ctx.effectiveOperandWidth;
            uint8_t reg = ModRM_Reg(ctx.modrm);
            if (ctx.rexR) reg |= 0x08;
            BuildRegOperand(operands[0], ResolveGPR(reg, sz, ctx.hasREX), sz);
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                uint8_t rm = ModRM_RM(ctx.modrm); if (ctx.rexB) rm |= 0x08;
                BuildRegOperand(operands[1], ResolveGPR(rm, sz, ctx.hasREX), sz);
            } else {
                BuildMemOperand(operands[1], ctx, 0, sz);
            }
            BuildImmOperand(operands[2], immediate, (op == 0x6B) ? 8 : sz, true);
            instruction.operand_count = 3;
            instruction.operand_count_visible = 3;
        }
    }
    // 2-byte opcode operands
    else if (ctx.opcodeMap == 1) {
        uint8_t op = ctx.opcode;
        if (op >= 0x80 && op <= 0x8F) {
            uint16_t sz = (ctx.effectiveOperandWidth == 16) ? 16 : 32;
            BuildImmOperand(operands[0], immediate, sz, true, true);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
            instruction.attributes |= ATTRIB_IS_RELATIVE;
        } else if (op >= 0xC8 && op <= 0xCF) {
            uint16_t sz = ctx.effectiveOperandWidth;
            uint8_t reg = op & 0x07; if (ctx.rexB) reg |= 0x08;
            BuildRegOperand(operands[0], ResolveGPR(reg, sz, ctx.hasREX), sz);
            instruction.operand_count = 1;
            instruction.operand_count_visible = 1;
        } else if (ctx.hasModRM) {
            uint16_t sz = ctx.effectiveOperandWidth;
            if (op >= 0x90 && op <= 0x9F) {
                uint8_t mod = ModRM_Mod(ctx.modrm);
                if (mod == kMod_Register) {
                    uint8_t rm = ModRM_RM(ctx.modrm); if (ctx.rexB) rm |= 0x08;
                    BuildRegOperand(operands[0], ResolveGPR(rm, 8, ctx.hasREX), 8);
                } else {
                    BuildMemOperand(operands[0], ctx, 0, 8);
                }
                instruction.operand_count = 1;
                instruction.operand_count_visible = 1;
            } else if (op == 0xB6 || op == 0xBE) {
                DecodeModRMOperands(ctx, instruction, operands, sz, 8, true);
            } else if (op == 0xB7 || op == 0xBF) {
                DecodeModRMOperands(ctx, instruction, operands, sz, 16, true);
            } else {
                DecodeModRMOperands(ctx, instruction, operands, sz, sz, true);
            }
        }
    }
    // 3-byte opcode operands
    else if ((ctx.opcodeMap == 2 || ctx.opcodeMap == 3) && ctx.hasModRM) {
        uint16_t sz = 128;
        DecodeModRMOperands(ctx, instruction, operands, sz, sz, true);
        if (ctx.opcodeMap == 3 && immSize > 0 && instruction.operand_count < MAX_OPERANDS) {
            BuildImmOperand(operands[instruction.operand_count], immediate, 8, false);
            instruction.operand_count++;
            instruction.operand_count_visible++;
        }
    }

    return Status::Success;
}

// ============================================================================
// Phase 1: DecodePrefixes
// ============================================================================

Status Decoder::DecodePrefixes(DecodeContext& ctx) noexcept {
    while (ctx.offset < ctx.bufferLength && ctx.offset < MAX_INSTRUCTION_LENGTH) {
        uint8_t b = ctx.buffer[ctx.offset];
        if (m_mode == MachineMode::Long64 && b >= kREXBase && b <= kREXMax) {
            ctx.hasREX = true;
            ctx.rexW = (b & kREX_W) != 0;
            ctx.rexR = (b & kREX_R) != 0;
            ctx.rexX = (b & kREX_X) != 0;
            ctx.rexB = (b & kREX_B) != 0;
            ctx.prefixCount++; ctx.offset++;
            break;
        }
        switch (b) {
        case kPrefixLOCK:  ctx.hasLock = true; break;
        case kPrefixREP:   ctx.hasRep = true; break;
        case kPrefixREPNE: ctx.hasRepNE = true; break;
        case kPrefixCS: ctx.hasSegOverride = true; ctx.segOverride = Register::CS; break;
        case kPrefixSS: ctx.hasSegOverride = true; ctx.segOverride = Register::SS; break;
        case kPrefixDS: ctx.hasSegOverride = true; ctx.segOverride = Register::DS; break;
        case kPrefixES: ctx.hasSegOverride = true; ctx.segOverride = Register::ES; break;
        case kPrefixFS: ctx.hasSegOverride = true; ctx.segOverride = Register::FS; break;
        case kPrefixGS: ctx.hasSegOverride = true; ctx.segOverride = Register::GS; break;
        case kPrefixOpSize:   ctx.hasOpSizeOverride = true; break;
        case kPrefixAddrSize: ctx.hasAddrSizeOverride = true; break;
        default: return Status::Success;
        }
        ctx.prefixCount++; ctx.offset++;
    }
    return Status::Success;
}

// ============================================================================
// Phase 1b: DecodeVEX
// ============================================================================

Status Decoder::DecodeVEX(DecodeContext& ctx) noexcept {
    if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
    uint8_t lead = ctx.buffer[ctx.offset];

    if (lead == kVEX2Byte) {
        if (ctx.offset + 1 >= ctx.bufferLength) return Status::TruncatedInput;
        uint8_t b1 = ctx.buffer[ctx.offset + 1];
        if (m_mode != MachineMode::Long64 && (b1 & 0xC0) != 0xC0) return Status::Success;
        ctx.offset += 2; ctx.prefixCount += 2;
        ctx.hasVEX = true; ctx.hasREX = true;
        ctx.rexR = ((b1 >> 7) & 1) == 0;
        ctx.rexX = false; ctx.rexB = false; ctx.vexW = false;
        ctx.vexVVVV = static_cast<uint8_t>((~(b1 >> 3)) & 0x0F);
        ctx.vexL = (b1 >> 2) & 1; ctx.vexPP = b1 & 0x03; ctx.vexMMMMM = 1;
        if (ctx.vexPP == 1) ctx.hasOpSizeOverride = true;
        else if (ctx.vexPP == 2) ctx.hasRep = true;
        else if (ctx.vexPP == 3) ctx.hasRepNE = true;
        return Status::Success;
    }
    if (lead == kVEX3Byte) {
        if (ctx.offset + 2 >= ctx.bufferLength) return Status::TruncatedInput;
        uint8_t b1 = ctx.buffer[ctx.offset + 1];
        uint8_t b2 = ctx.buffer[ctx.offset + 2];
        if (m_mode != MachineMode::Long64 && (b1 & 0xC0) != 0xC0) return Status::Success;
        ctx.offset += 3; ctx.prefixCount += 3;
        ctx.hasVEX = true; ctx.hasREX = true;
        ctx.rexR = ((b1 >> 7) & 1) == 0;
        ctx.rexX = ((b1 >> 6) & 1) == 0;
        ctx.rexB = ((b1 >> 5) & 1) == 0;
        ctx.vexMMMMM = b1 & 0x1F;
        if (ctx.vexMMMMM == 0 || ctx.vexMMMMM > 3) return Status::InvalidPrefix;
        ctx.vexW = ((b2 >> 7) & 1) != 0; ctx.rexW = ctx.vexW;
        ctx.vexVVVV = static_cast<uint8_t>((~(b2 >> 3)) & 0x0F);
        ctx.vexL = (b2 >> 2) & 1; ctx.vexPP = b2 & 0x03;
        if (ctx.vexPP == 1) ctx.hasOpSizeOverride = true;
        else if (ctx.vexPP == 2) ctx.hasRep = true;
        else if (ctx.vexPP == 3) ctx.hasRepNE = true;
        return Status::Success;
    }
    return Status::Success;
}

// ============================================================================
// Phase 1c: DecodeEVEX
// ============================================================================

Status Decoder::DecodeEVEX(DecodeContext& ctx) noexcept {
    if (ctx.offset + 3 >= ctx.bufferLength) return Status::TruncatedInput;
    uint8_t p1 = ctx.buffer[ctx.offset + 1];
    uint8_t p2 = ctx.buffer[ctx.offset + 2];
    uint8_t p3 = ctx.buffer[ctx.offset + 3];
    if (m_mode != MachineMode::Long64) {
        if ((p1 & 0x0C) != 0x00 || (p2 & 0x04) == 0) return Status::Success;
    }
    ctx.offset += 4; ctx.prefixCount += 4;
    ctx.hasEVEX = true; ctx.hasREX = true;
    ctx.rexR = ((p1 >> 7) & 1) == 0;
    ctx.rexX = ((p1 >> 6) & 1) == 0;
    ctx.rexB = ((p1 >> 5) & 1) == 0;
    ctx.evexR2 = ((p1 >> 4) & 1) == 0 ? 1 : 0;
    ctx.vexMMMMM = p1 & 0x03;
    ctx.vexW = ((p2 >> 7) & 1) != 0; ctx.rexW = ctx.vexW;
    ctx.vexVVVV = static_cast<uint8_t>((~(p2 >> 3)) & 0x0F);
    ctx.vexPP = p2 & 0x03;
    ctx.evexZ = (p3 >> 7) & 1; ctx.evexLL = (p3 >> 5) & 0x03;
    ctx.evexB = (p3 >> 4) & 1;
    ctx.evexV2 = ((p3 >> 3) & 1) == 0 ? 1 : 0;
    ctx.evexAAA = p3 & 0x07;
    if (ctx.vexPP == 1) ctx.hasOpSizeOverride = true;
    else if (ctx.vexPP == 2) ctx.hasRep = true;
    else if (ctx.vexPP == 3) ctx.hasRepNE = true;
    if (ctx.vexMMMMM == 0 || ctx.vexMMMMM > 3) return Status::InvalidPrefix;
    return Status::Success;
}

// ============================================================================
// Phase 2: DecodeOpcode
// ============================================================================

Status Decoder::DecodeOpcode(DecodeContext& ctx) noexcept {
    if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
    uint8_t b = ctx.buffer[ctx.offset++];
    if (b != kTwoByteEscape) { ctx.opcodeMap = 0; ctx.opcode = b; return Status::Success; }
    if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
    b = ctx.buffer[ctx.offset];
    if (b == kThreeByteEsc38) {
        ctx.offset++;
        if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
        ctx.opcodeMap = 2; ctx.opcode = ctx.buffer[ctx.offset++]; return Status::Success;
    }
    if (b == kThreeByteEsc3A) {
        ctx.offset++;
        if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
        ctx.opcodeMap = 3; ctx.opcode = ctx.buffer[ctx.offset++]; return Status::Success;
    }
    ctx.opcodeMap = 1; ctx.opcode = b; ctx.offset++; return Status::Success;
}

// ============================================================================
// Phase 3-6: ModRM, SIB, Displacement, Immediate
// ============================================================================

Status Decoder::DecodeModRM(DecodeContext& ctx) noexcept {
    if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
    ctx.modrm = ctx.buffer[ctx.offset++];
    ctx.hasModRM = true;
    ctx.opcodeExt = ModRM_Reg(ctx.modrm);
    return Status::Success;
}

Status Decoder::DecodeSIB(DecodeContext& ctx) noexcept {
    if (ctx.offset >= ctx.bufferLength) return Status::TruncatedInput;
    ctx.sib = ctx.buffer[ctx.offset++];
    ctx.hasSIB = true;
    return Status::Success;
}

Status Decoder::DecodeDisplacement(DecodeContext& ctx, uint8_t dispSize, int64_t& disp) noexcept {
    disp = 0;
    switch (dispSize) {
    case 1: { uint8_t v; if (!ReadByte(ctx,ctx.offset,v)) return Status::TruncatedInput; disp=SignExtend8(v); ctx.offset+=1; break; }
    case 2: { uint16_t v; if (!ReadWord(ctx,ctx.offset,v)) return Status::TruncatedInput; disp=SignExtend16(v); ctx.offset+=2; break; }
    case 4: { uint32_t v; if (!ReadDword(ctx,ctx.offset,v)) return Status::TruncatedInput; disp=SignExtend32(v); ctx.offset+=4; break; }
    default: return Status::InvalidModRM;
    }
    return Status::Success;
}

Status Decoder::DecodeImmediate(DecodeContext& ctx, uint8_t immSize, int64_t& imm) noexcept {
    imm = 0;
    switch (immSize) {
    case 1: { uint8_t v; if (!ReadByte(ctx,ctx.offset,v)) return Status::TruncatedInput; imm=SignExtend8(v); ctx.offset+=1; break; }
    case 2: { uint16_t v; if (!ReadWord(ctx,ctx.offset,v)) return Status::TruncatedInput; imm=SignExtend16(v); ctx.offset+=2; break; }
    case 3: { uint16_t lo; uint8_t hi;
              if (!ReadWord(ctx,ctx.offset,lo)) return Status::TruncatedInput;
              if (!ReadByte(ctx,ctx.offset+2,hi)) return Status::TruncatedInput;
              imm = static_cast<int64_t>(lo) | (static_cast<int64_t>(hi)<<16); ctx.offset+=3; break; }
    case 4: { uint32_t v; if (!ReadDword(ctx,ctx.offset,v)) return Status::TruncatedInput; imm=SignExtend32(v); ctx.offset+=4; break; }
    case 8: { uint64_t v; if (!ReadQword(ctx,ctx.offset,v)) return Status::TruncatedInput; imm=static_cast<int64_t>(v); ctx.offset+=8; break; }
    default: return Status::InvalidOpcode;
    }
    return Status::Success;
}

// ============================================================================
// OpcodeRequiresModRM
// ============================================================================

bool Decoder::OpcodeRequiresModRM(uint8_t map, uint8_t opcode) const noexcept {
    if (map == 2 || map == 3) return true; // 3-byte: all require ModRM

    if (map == 1) {
        // 2-byte: almost all require ModRM except these
        switch (opcode) {
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B: case 0x0E:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x37:
        case 0x77:
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            return false;
        default:
            return true;
        }
    }

    // 1-byte opcode map
    if (opcode <= 0x3F) {
        uint8_t low3 = opcode & 0x07;
        return (low3 <= 3);
    }
    if (opcode >= 0x40 && opcode <= 0x4F) return false;
    if (opcode >= 0x50 && opcode <= 0x5F) return false;

    switch (opcode) {
    case 0x60: case 0x61: return false;
    case 0x62: return true;
    case 0x63: return true;
    case 0x68: return false;
    case 0x69: return true;
    case 0x6A: return false;
    case 0x6B: return true;
    case 0x6C: case 0x6D: case 0x6E: case 0x6F: return false;
    }

    if (opcode >= 0x70 && opcode <= 0x7F) return false;
    if (opcode >= 0x80 && opcode <= 0x83) return true;

    switch (opcode) {
    case 0x84: case 0x85: case 0x86: case 0x87: return true;
    case 0x88: case 0x89: case 0x8A: case 0x8B: return true;
    case 0x8C: case 0x8D: case 0x8E: return true;
    case 0x8F: return true;
    }

    if (opcode >= 0x90 && opcode <= 0x97) return false;
    switch (opcode) {
    case 0x98: case 0x99: case 0x9A: case 0x9B: return false;
    case 0x9C: case 0x9D: case 0x9E: case 0x9F: return false;
    }

    if (opcode >= 0xA0 && opcode <= 0xAF) return false;
    if (opcode >= 0xB0 && opcode <= 0xBF) return false;

    switch (opcode) {
    case 0xC0: case 0xC1: return true;
    case 0xC2: case 0xC3: return false;
    case 0xC4: case 0xC5: return true;
    case 0xC6: case 0xC7: return true;
    case 0xC8: case 0xC9: return false;
    case 0xCA: case 0xCB: return false;
    case 0xCC: case 0xCD: case 0xCE: case 0xCF: return false;
    }

    if (opcode >= 0xD0 && opcode <= 0xD3) return true;
    switch (opcode) {
    case 0xD4: case 0xD5: case 0xD6: case 0xD7: return false;
    }
    if (opcode >= 0xD8 && opcode <= 0xDF) return true;
    if (opcode >= 0xE0 && opcode <= 0xEF) return false;

    switch (opcode) {
    case 0xF0: case 0xF1: case 0xF2: case 0xF3: return false;
    case 0xF4: case 0xF5: return false;
    case 0xF6: case 0xF7: return true;
    case 0xF8: case 0xF9: case 0xFA: case 0xFB: return false;
    case 0xFC: case 0xFD: return false;
    case 0xFE: case 0xFF: return true;
    }
    return false;
}

// ============================================================================
// OpcodeImmediateSize
// ============================================================================

uint8_t Decoder::OpcodeImmediateSize(uint8_t map, uint8_t opcode,
                                      uint16_t opWidth) const noexcept {
    if (map == 3) return 1; // 0F3A: all have 1-byte imm

    if (map == 2) return 0; // 0F38: no immediates (except handled specially)

    if (map == 1) {
        // 2-byte opcodes with immediates
        switch (opcode) {
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0xC2: case 0xC4: case 0xC5: case 0xC6: case 0xBA:
            return 1;
        // Jcc rel16/32 and SHLD/SHRD handled in DecodeFull
        default: return 0;
        }
    }

    // 1-byte opcode map
    if (opcode <= 0x3F) {
        uint8_t low3 = opcode & 0x07;
        if (low3 == 4) return 1;
        if (low3 == 5) return (opWidth == 16) ? 2 : 4;
        return 0;
    }

    switch (opcode) {
    case 0x68: return (opWidth == 16) ? 2 : 4;
    case 0x6A: return 1;
    case 0x69: return (opWidth == 16) ? 2 : 4;
    case 0x6B: return 1;

    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        return 1;

    case 0x80: case 0x82: return 1;
    case 0x81: return (opWidth == 16) ? 2 : 4;
    case 0x83: return 1;

    case 0xA8: return 1;
    case 0xA9: return (opWidth == 16) ? 2 : 4;

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        return 1;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        return (opWidth == 64) ? 8 : ((opWidth == 16) ? 2 : 4);

    case 0xC0: case 0xC1: return 1;
    case 0xC2: case 0xCA: return 2;
    case 0xC6: return 1;
    case 0xC7: return (opWidth == 16) ? 2 : 4;
    case 0xC8: return 3;
    case 0xCD: return 1;

    case 0xE0: case 0xE1: case 0xE2: case 0xE3: return 1;
    case 0xE4: case 0xE5: case 0xE6: case 0xE7: return 1;
    case 0xE8: return (opWidth == 16) ? 2 : 4;
    case 0xE9: return (opWidth == 16) ? 2 : 4;
    case 0xEB: return 1;

    // F6/F7 TEST handled in DecodeFull
    case 0xF6: case 0xF7: return 0;

    default: return 0;
    }
}

// ============================================================================
// ResolveMnemonic - maps (opcodeMap, opcode, ext, prefix) to Mnemonic
// ============================================================================

Mnemonic Decoder::ResolveMnemonic(const DecodeContext& ctx) const noexcept {
    const uint8_t map = ctx.opcodeMap;
    const uint8_t op  = ctx.opcode;
    const uint8_t ext = ctx.opcodeExt;

    // ---- 1-byte opcode map ----
    if (map == 0) {
        // ALU ops: 00-05=ADD, 08-0D=OR, 10-15=ADC, 18-1D=SBB, 20-25=AND, 28-2D=SUB, 30-35=XOR, 38-3D=CMP
        if (op <= 0x3F) {
            uint8_t row = op >> 3;
            switch (row) {
            case 0: return Mnemonic::ADD;
            case 1: return Mnemonic::OR;
            case 2: return Mnemonic::ADC;
            case 3: return Mnemonic::SBB;
            case 4: return Mnemonic::AND;
            case 5: return Mnemonic::SUB;
            case 6: return Mnemonic::XOR;
            case 7: return Mnemonic::CMP;
            default: break;
            }
            // Segment push/pop and BCD ops in the gaps
            switch (op) {
            case 0x06: case 0x0E: case 0x16: case 0x1E: return Mnemonic::PUSH;
            case 0x07: case 0x17: case 0x1F: return Mnemonic::POP;
            case 0x27: return Mnemonic::UNKNOWN; // DAA
            case 0x2F: return Mnemonic::UNKNOWN; // DAS
            case 0x37: return Mnemonic::UNKNOWN; // AAA
            case 0x3F: return Mnemonic::UNKNOWN; // AAS
            default: break;
            }
        }

        // 40-4F: INC/DEC (32-bit) — in 64-bit mode these are REX prefixes
        if (op >= 0x40 && op <= 0x47) return Mnemonic::INC;
        if (op >= 0x48 && op <= 0x4F) return Mnemonic::DEC;

        // 50-57: PUSH, 58-5F: POP
        if (op >= 0x50 && op <= 0x57) return Mnemonic::PUSH;
        if (op >= 0x58 && op <= 0x5F) return Mnemonic::POP;

        // 60-6F
        switch (op) {
        case 0x60: return Mnemonic::PUSHA;
        case 0x61: return Mnemonic::POPA;
        case 0x62: return Mnemonic::UNKNOWN; // BOUND
        case 0x63:
            return (m_mode == MachineMode::Long64) ? Mnemonic::MOVSXD : Mnemonic::UNKNOWN;
        case 0x68: case 0x6A: return Mnemonic::PUSH;
        case 0x69: case 0x6B: return Mnemonic::IMUL;
        case 0x6C: return Mnemonic::INS;
        case 0x6D: return Mnemonic::INS;
        case 0x6E: return Mnemonic::OUTS;
        case 0x6F: return Mnemonic::OUTS;
        }

        // Jcc short (70-7F)
        switch (op) {
        case 0x70: return Mnemonic::JO;
        case 0x71: return Mnemonic::JNO;
        case 0x72: return Mnemonic::JB;
        case 0x73: return Mnemonic::JNB;
        case 0x74: return Mnemonic::JZ;
        case 0x75: return Mnemonic::JNZ;
        case 0x76: return Mnemonic::JBE;
        case 0x77: return Mnemonic::JNBE;
        case 0x78: return Mnemonic::JS;
        case 0x79: return Mnemonic::JNS;
        case 0x7A: return Mnemonic::JP;
        case 0x7B: return Mnemonic::JNP;
        case 0x7C: return Mnemonic::JL;
        case 0x7D: return Mnemonic::JNL;
        case 0x7E: return Mnemonic::JLE;
        case 0x7F: return Mnemonic::JNLE;
        default: break;
        }

        // Group 1: 80-83
        if (op >= 0x80 && op <= 0x83) {
            static constexpr Mnemonic grp1[8] = {
                Mnemonic::ADD, Mnemonic::OR, Mnemonic::ADC, Mnemonic::SBB,
                Mnemonic::AND, Mnemonic::SUB, Mnemonic::XOR, Mnemonic::CMP,
            };
            return grp1[ext & 7];
        }

        switch (op) {
        case 0x84: case 0x85: return Mnemonic::TEST;
        case 0x86: case 0x87: return Mnemonic::XCHG;
        case 0x88: case 0x89: case 0x8A: case 0x8B: return Mnemonic::MOV;
        case 0x8C: return Mnemonic::MOV;
        case 0x8D: return Mnemonic::LEA;
        case 0x8E: return Mnemonic::MOV;
        case 0x8F: return (ext == 0) ? Mnemonic::POP : Mnemonic::UNKNOWN;
        case 0x90:
            if (ctx.hasRep) return Mnemonic::PAUSE;
            return Mnemonic::NOP;
        case 0x91: case 0x92: case 0x93: case 0x94:
        case 0x95: case 0x96: case 0x97: return Mnemonic::XCHG;
        case 0x98:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::CDQE;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::CWDE;
            return Mnemonic::CBW;
        case 0x99:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::CQO;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::CDQ;
            return Mnemonic::CWD;
        case 0x9B: return Mnemonic::FWAIT;
        case 0x9C:
            return (m_mode == MachineMode::Long64) ? Mnemonic::PUSHFQ : Mnemonic::PUSHF;
        case 0x9D:
            return (m_mode == MachineMode::Long64) ? Mnemonic::POPFQ : Mnemonic::POPF;
        case 0x9E: return Mnemonic::SAHF;
        case 0x9F: return Mnemonic::LAHF;
        default: break;
        }

        switch (op) {
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: return Mnemonic::MOV;
        case 0xA4: return Mnemonic::MOVSB;
        case 0xA5:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::MOVSQ;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::MOVSD_STR;
            return Mnemonic::MOVSW;
        case 0xA6: return Mnemonic::CMPSB;
        case 0xA7:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::CMPSQ;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::CMPSD_STR;
            return Mnemonic::CMPSW;
        case 0xA8: case 0xA9: return Mnemonic::TEST;
        case 0xAA: return Mnemonic::STOSB;
        case 0xAB:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::STOSQ;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::STOSD;
            return Mnemonic::STOSW;
        case 0xAC: return Mnemonic::LODSB;
        case 0xAD:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::LODSQ;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::LODSD;
            return Mnemonic::LODSW;
        case 0xAE: return Mnemonic::SCASB;
        case 0xAF:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::SCASQ;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::SCASD;
            return Mnemonic::SCASW;
        default: break;
        }

        // B0-BF: MOV reg, imm
        if (op >= 0xB0 && op <= 0xBF) return Mnemonic::MOV;

        // Shift group (C0, C1, D0-D3)
        if (op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3)) {
            static constexpr Mnemonic grp2[8] = {
                Mnemonic::ROL, Mnemonic::ROR, Mnemonic::RCL, Mnemonic::RCR,
                Mnemonic::SHL, Mnemonic::SHR, Mnemonic::SAL, Mnemonic::SAR,
            };
            return grp2[ext & 7];
        }

        switch (op) {
        case 0xC2: return Mnemonic::RET;
        case 0xC3: return Mnemonic::RET;
        case 0xC4: return Mnemonic::UNKNOWN; // LES
        case 0xC5: return Mnemonic::UNKNOWN; // LDS
        case 0xC6: case 0xC7: return (ext == 0) ? Mnemonic::MOV : Mnemonic::UNKNOWN;
        case 0xC8: return Mnemonic::ENTER;
        case 0xC9: return Mnemonic::LEAVE;
        case 0xCA: return Mnemonic::RETF;
        case 0xCB: return Mnemonic::RETF;
        case 0xCC: return Mnemonic::INT3;
        case 0xCD: return Mnemonic::INT;
        case 0xCE: return Mnemonic::INTO;
        case 0xCF:
            if (ctx.effectiveOperandWidth == 64) return Mnemonic::IRETQ;
            if (ctx.effectiveOperandWidth == 32) return Mnemonic::IRETD;
            return Mnemonic::IRET;
        default: break;
        }

        switch (op) {
        case 0xD4: return Mnemonic::UNKNOWN; // AAM
        case 0xD5: return Mnemonic::UNKNOWN; // AAD
        case 0xD6: return Mnemonic::UNKNOWN; // SALC
        case 0xD7: return Mnemonic::UNKNOWN; // XLAT
        default: break;
        }

        // FPU opcodes D8-DF: decoded by helper
        if (op >= 0xD8 && op <= 0xDF) {
            return ResolveFPUMnemonicImpl(op, ctx.modrm);
        }

        // E0-EF
        switch (op) {
        case 0xE0: return Mnemonic::LOOPNE;
        case 0xE1: return Mnemonic::LOOPE;
        case 0xE2: return Mnemonic::LOOP;
        case 0xE3:
            if (m_mode == MachineMode::Long64) return Mnemonic::JRCXZ;
            if (ctx.effectiveAddressWidth == 32) return Mnemonic::JECXZ;
            return Mnemonic::JCXZ;
        case 0xE4: case 0xE5: case 0xEC: case 0xED: return Mnemonic::IN;
        case 0xE6: case 0xE7: case 0xEE: case 0xEF: return Mnemonic::OUT;
        case 0xE8: return Mnemonic::CALL;
        case 0xE9: case 0xEB: return Mnemonic::JMP;
        case 0xEA: return Mnemonic::JMP; // far
        default: break;
        }

        // F0-FF
        switch (op) {
        case 0xF0: return Mnemonic::LOCK_PREFIX;
        case 0xF1: return Mnemonic::INT1;
        case 0xF4: return Mnemonic::HLT;
        case 0xF5: return Mnemonic::CMC;
        case 0xF6: case 0xF7: {
            static constexpr Mnemonic grp3[8] = {
                Mnemonic::TEST, Mnemonic::TEST, Mnemonic::NOT, Mnemonic::NEG,
                Mnemonic::MUL, Mnemonic::IMUL, Mnemonic::DIV, Mnemonic::IDIV,
            };
            return grp3[ext & 7];
        }
        case 0xF8: return Mnemonic::CLC;
        case 0xF9: return Mnemonic::STC;
        case 0xFA: return Mnemonic::CLI;
        case 0xFB: return Mnemonic::STI;
        case 0xFC: return Mnemonic::CLD;
        case 0xFD: return Mnemonic::STD;
        case 0xFE: {
            if (ext == 0) return Mnemonic::INC;
            if (ext == 1) return Mnemonic::DEC;
            return Mnemonic::UNKNOWN;
        }
        case 0xFF: {
            static constexpr Mnemonic grp5[8] = {
                Mnemonic::INC, Mnemonic::DEC, Mnemonic::CALL, Mnemonic::CALL,
                Mnemonic::JMP, Mnemonic::JMP, Mnemonic::PUSH, Mnemonic::UNKNOWN,
            };
            return grp5[ext & 7];
        }
        default: break;
        }

        return Mnemonic::UNKNOWN;
    } // end map==0

    // ---- 2-byte opcode map (0F xx) ----
    if (map == 1) {
        // System instructions
        switch (op) {
        case 0x00: {
            static constexpr Mnemonic grp6[8] = {
                Mnemonic::SLDT, Mnemonic::STR, Mnemonic::LLDT, Mnemonic::LTR,
                Mnemonic::VERR, Mnemonic::VERW, Mnemonic::UNKNOWN, Mnemonic::UNKNOWN,
            };
            return grp6[ext & 7];
        }
        case 0x01: {
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod != kMod_Register) {
                static constexpr Mnemonic grp7mem[8] = {
                    Mnemonic::SGDT, Mnemonic::SIDT, Mnemonic::LGDT, Mnemonic::LIDT,
                    Mnemonic::SMSW, Mnemonic::UNKNOWN, Mnemonic::LMSW, Mnemonic::INVLPG,
                };
                return grp7mem[ext & 7];
            }
            // mod==3 special cases
            uint8_t rm = ModRM_RM(ctx.modrm);
            if (ext == 0) {
                if (rm == 1) return Mnemonic::UNKNOWN; // VMCALL
                if (rm == 2) return Mnemonic::UNKNOWN; // VMLAUNCH
            }
            if (ext == 1) {
                if (rm == 0) return Mnemonic::UNKNOWN; // MONITOR
                if (rm == 1) return Mnemonic::UNKNOWN; // MWAIT
            }
            if (ext == 2) {
                if (rm == 0) return Mnemonic::XGETBV;
                if (rm == 1) return Mnemonic::XSETBV;
            }
            if (ext == 4) return Mnemonic::SMSW;
            if (ext == 6) return Mnemonic::LMSW;
            if (ext == 7) {
                if (rm == 0) return Mnemonic::SWAPGS;
                if (rm == 1) return Mnemonic::RDTSCP;
            }
            return Mnemonic::UNKNOWN;
        }
        case 0x02: return Mnemonic::LAR;
        case 0x03: return Mnemonic::LSL;
        case 0x05: return Mnemonic::SYSCALL;
        case 0x06: return Mnemonic::CLTS;
        case 0x07: return Mnemonic::SYSRET;
        case 0x08: return Mnemonic::INVD;
        case 0x09: return Mnemonic::WBINVD;
        case 0x0B: return Mnemonic::UD2;
        case 0x0D: return Mnemonic::UNKNOWN; // PREFETCH group
        case 0x0E: return Mnemonic::UNKNOWN; // FEMMS
        default: break;
        }

        // SSE data movement (10-17)
        if (op >= 0x10 && op <= 0x17) {
            if (ctx.hasRepNE) {
                switch (op) {
                case 0x10: case 0x11: return Mnemonic::MOVSD_SSE;
                case 0x12: return Mnemonic::MOVDDUP;
                default: return Mnemonic::UNKNOWN;
                }
            }
            if (ctx.hasRep) {
                switch (op) {
                case 0x10: case 0x11: return Mnemonic::MOVSS;
                case 0x12: return Mnemonic::UNKNOWN; // MOVSLDUP
                case 0x16: return Mnemonic::UNKNOWN; // MOVSHDUP
                default: return Mnemonic::UNKNOWN;
                }
            }
            if (ctx.hasOpSizeOverride) {
                switch (op) {
                case 0x10: case 0x11: return Mnemonic::MOVUPD;
                case 0x12: case 0x13: return Mnemonic::MOVLPD;
                case 0x14: return Mnemonic::UNPCKLPD;
                case 0x15: return Mnemonic::UNPCKHPD;
                case 0x16: case 0x17: return Mnemonic::MOVHPD;
                default: return Mnemonic::UNKNOWN;
                }
            }
            switch (op) {
            case 0x10: case 0x11: return Mnemonic::MOVUPS;
            case 0x12: case 0x13: return Mnemonic::MOVLPS;
            case 0x14: return Mnemonic::UNPCKLPS;
            case 0x15: return Mnemonic::UNPCKHPS;
            case 0x16: case 0x17: return Mnemonic::MOVHPS;
            default: return Mnemonic::UNKNOWN;
            }
        }

        if (op == 0x18) {
            switch (ext) {
            case 0: return Mnemonic::PREFETCHNTA;
            case 1: return Mnemonic::PREFETCHT0;
            case 2: return Mnemonic::PREFETCHT1;
            case 3: return Mnemonic::PREFETCHT2;
            default: return Mnemonic::NOP;
            }
        }
        if (op >= 0x19 && op <= 0x1E) return Mnemonic::NOP;
        if (op == 0x1F) {
            if (ext == 0 && ctx.modrm == 0xFA) return Mnemonic::ENDBR64;
            if (ext == 0 && ctx.modrm == 0xFB) return Mnemonic::ENDBR32;
            return Mnemonic::NOP;
        }

        switch (op) {
        case 0x20: case 0x22: return Mnemonic::MOV; // MOV CR
        case 0x21: case 0x23: return Mnemonic::MOV; // MOV DR
        default: break;
        }

        // SSE moves/converts (28-2F)
        if (op >= 0x28 && op <= 0x2F) {
            if (ctx.hasRepNE) {
                switch (op) {
                case 0x2A: return Mnemonic::CVTSI2SD;
                case 0x2C: return Mnemonic::CVTTSD2SI;
                case 0x2D: return Mnemonic::CVTSD2SI;
                default: return Mnemonic::UNKNOWN;
                }
            }
            if (ctx.hasRep) {
                switch (op) {
                case 0x2A: return Mnemonic::CVTSI2SS;
                case 0x2C: return Mnemonic::CVTTSS2SI;
                case 0x2D: return Mnemonic::CVTSS2SI;
                default: return Mnemonic::UNKNOWN;
                }
            }
            if (ctx.hasOpSizeOverride) {
                switch (op) {
                case 0x28: case 0x29: return Mnemonic::MOVAPD;
                case 0x2A: return Mnemonic::CVTPI2PD;
                case 0x2B: return Mnemonic::MOVNTPD;
                case 0x2C: return Mnemonic::CVTTPD2PI;
                case 0x2D: return Mnemonic::CVTPD2PI;
                case 0x2E: return Mnemonic::UCOMISD;
                case 0x2F: return Mnemonic::COMISD;
                default: return Mnemonic::UNKNOWN;
                }
            }
            switch (op) {
            case 0x28: case 0x29: return Mnemonic::MOVAPS;
            case 0x2A: return Mnemonic::CVTPI2PS;
            case 0x2B: return Mnemonic::MOVNTPS;
            case 0x2C: return Mnemonic::CVTTPS2PI;
            case 0x2D: return Mnemonic::CVTPS2PI;
            case 0x2E: return Mnemonic::UCOMISS;
            case 0x2F: return Mnemonic::COMISS;
            default: return Mnemonic::UNKNOWN;
            }
        }

        switch (op) {
        case 0x30: return Mnemonic::WRMSR;
        case 0x31: return Mnemonic::RDTSC;
        case 0x32: return Mnemonic::RDMSR;
        case 0x33: return Mnemonic::RDPMC;
        case 0x34: return Mnemonic::SYSENTER;
        case 0x35: return Mnemonic::SYSEXIT;
        case 0x37: return Mnemonic::UNKNOWN; // GETSEC
        default: break;
        }

        // CMOVcc (40-4F)
        if (op >= 0x40 && op <= 0x4F) {
            static constexpr Mnemonic cmov[16] = {
                Mnemonic::CMOVO, Mnemonic::CMOVNO, Mnemonic::CMOVB, Mnemonic::CMOVNB, Mnemonic::CMOVZ, Mnemonic::CMOVNZ, Mnemonic::CMOVBE, Mnemonic::CMOVNBE,
                Mnemonic::CMOVS, Mnemonic::CMOVNS, Mnemonic::CMOVP, Mnemonic::CMOVNP, Mnemonic::CMOVL, Mnemonic::CMOVNL, Mnemonic::CMOVLE, Mnemonic::CMOVNLE,
            };
            return cmov[op - 0x40];
        }

        // SSE operations (50-5F)
        if (op >= 0x50 && op <= 0x5F) {
            // Determine prefix type for SSE disambiguation
            // Priority: F2 > F3 > 66 > none
            uint8_t pfx = 0; // 0=none, 1=66, 2=F3, 3=F2
            if (ctx.hasRepNE && !ctx.hasVEX && !ctx.hasEVEX) pfx = 3;
            else if (ctx.hasRep && !ctx.hasVEX && !ctx.hasEVEX) pfx = 2;
            else if (ctx.hasRepNE) pfx = 3;
            else if (ctx.hasRep) pfx = 2;
            else if (ctx.hasOpSizeOverride) pfx = 1;

            // [none, 66, F3, F2] for each opcode
            static constexpr Mnemonic sse5x[16][4] = {
                /* 50 */ { Mnemonic::MOVMSKPS, Mnemonic::MOVMSKPD, Mnemonic::UNKNOWN, Mnemonic::UNKNOWN },
                /* 51 */ { Mnemonic::SQRTPS, Mnemonic::SQRTPD, Mnemonic::SQRTSS, Mnemonic::SQRTSD },
                /* 52 */ { Mnemonic::RSQRTPS, Mnemonic::UNKNOWN, Mnemonic::RSQRTSS, Mnemonic::UNKNOWN },
                /* 53 */ { Mnemonic::RCPPS, Mnemonic::UNKNOWN, Mnemonic::RCPSS, Mnemonic::UNKNOWN },
                /* 54 */ { Mnemonic::ANDPS, Mnemonic::ANDPD, Mnemonic::UNKNOWN, Mnemonic::UNKNOWN },
                /* 55 */ { Mnemonic::ANDNPS, Mnemonic::ANDNPD, Mnemonic::UNKNOWN, Mnemonic::UNKNOWN },
                /* 56 */ { Mnemonic::ORPS, Mnemonic::ORPD, Mnemonic::UNKNOWN, Mnemonic::UNKNOWN },
                /* 57 */ { Mnemonic::XORPS, Mnemonic::XORPD, Mnemonic::UNKNOWN, Mnemonic::UNKNOWN },
                /* 58 */ { Mnemonic::ADDPS, Mnemonic::ADDPD, Mnemonic::ADDSS, Mnemonic::ADDSD },
                /* 59 */ { Mnemonic::MULPS, Mnemonic::MULPD, Mnemonic::MULSS, Mnemonic::MULSD },
                /* 5A */ { Mnemonic::CVTPS2PD, Mnemonic::CVTPD2PS, Mnemonic::CVTSS2SD, Mnemonic::CVTSD2SS },
                /* 5B */ { Mnemonic::CVTDQ2PS, Mnemonic::CVTPS2DQ, Mnemonic::CVTTPS2DQ, Mnemonic::UNKNOWN },
                /* 5C */ { Mnemonic::SUBPS, Mnemonic::SUBPD, Mnemonic::SUBSS, Mnemonic::SUBSD },
                /* 5D */ { Mnemonic::MINPS, Mnemonic::MINPD, Mnemonic::MINSS, Mnemonic::MINSD },
                /* 5E */ { Mnemonic::DIVPS, Mnemonic::DIVPD, Mnemonic::DIVSS, Mnemonic::DIVSD },
                /* 5F */ { Mnemonic::MAXPS, Mnemonic::MAXPD, Mnemonic::MAXSS, Mnemonic::MAXSD },
            };
            return sse5x[op - 0x50][pfx];
        }

        // Packed integer (60-6F)
        if (op >= 0x60 && op <= 0x6F) {
            switch (op) {
            case 0x60: return Mnemonic::PUNPCKLBW;
            case 0x61: return Mnemonic::PUNPCKLWD;
            case 0x62: return Mnemonic::PUNPCKLDQ;
            case 0x63: return Mnemonic::PACKSSWB;
            case 0x64: return Mnemonic::PCMPGTB;
            case 0x65: return Mnemonic::PCMPGTW;
            case 0x66: return Mnemonic::PCMPGTD;
            case 0x67: return Mnemonic::PACKUSWB;
            case 0x68: return Mnemonic::PUNPCKHBW;
            case 0x69: return Mnemonic::PUNPCKHWD;
            case 0x6A: return Mnemonic::PUNPCKHDQ;
            case 0x6B: return Mnemonic::PACKSSDW;
            case 0x6C: return Mnemonic::PUNPCKLQDQ;
            case 0x6D: return Mnemonic::PUNPCKHQDQ;
            case 0x6E: return Mnemonic::MOVD_SSE;
            case 0x6F:
                if (ctx.hasRep) return Mnemonic::MOVDQU;
                if (ctx.hasOpSizeOverride) return Mnemonic::MOVDQA;
                return Mnemonic::MOVQ_SSE;
            default: return Mnemonic::UNKNOWN;
            }
        }

        // SSE shuffle/compare (70-7F)
        if (op >= 0x70 && op <= 0x7F) {
            switch (op) {
            case 0x70:
                if (ctx.hasRepNE) return Mnemonic::PSHUFLW;
                if (ctx.hasRep) return Mnemonic::PSHUFHW;
                if (ctx.hasOpSizeOverride) return Mnemonic::PSHUFD;
                return Mnemonic::UNKNOWN; // PSHUFW (MMX)
            case 0x71: // Group 12: PSRLW/PSRAW/PSLLW
                if (ext == 2) return Mnemonic::PSRLW;
                if (ext == 4) return Mnemonic::PSRAW;
                if (ext == 6) return Mnemonic::PSLLW;
                return Mnemonic::UNKNOWN;
            case 0x72: // Group 13: PSRLD/PSRAD/PSLLD
                if (ext == 2) return Mnemonic::PSRLD;
                if (ext == 4) return Mnemonic::PSRAD;
                if (ext == 6) return Mnemonic::PSLLD;
                return Mnemonic::UNKNOWN;
            case 0x73: // Group 14: PSRLQ/PSLLQ
                if (ext == 2) return Mnemonic::PSRLQ;
                if (ext == 3) return Mnemonic::UNKNOWN; // PSRLDQ
                if (ext == 6) return Mnemonic::PSLLQ;
                if (ext == 7) return Mnemonic::UNKNOWN; // PSLLDQ
                return Mnemonic::UNKNOWN;
            case 0x74: return Mnemonic::PCMPEQB;
            case 0x75: return Mnemonic::PCMPEQW;
            case 0x76: return Mnemonic::PCMPEQD;
            case 0x77: return Mnemonic::EMMS;
            case 0x7E:
                if (ctx.hasRep) return Mnemonic::MOVQ_SSE;
                return Mnemonic::MOVD_SSE;
            case 0x7F:
                if (ctx.hasRep) return Mnemonic::MOVDQU;
                if (ctx.hasOpSizeOverride) return Mnemonic::MOVDQA;
                return Mnemonic::MOVQ_SSE;
            default: return Mnemonic::UNKNOWN;
            }
        }

        // Jcc rel16/32 (80-8F)
        if (op >= 0x80 && op <= 0x8F) {
            static constexpr Mnemonic jcc[16] = {
                Mnemonic::JO, Mnemonic::JNO, Mnemonic::JB, Mnemonic::JNB, Mnemonic::JZ, Mnemonic::JNZ, Mnemonic::JBE, Mnemonic::JNBE,
                Mnemonic::JS, Mnemonic::JNS, Mnemonic::JP, Mnemonic::JNP, Mnemonic::JL, Mnemonic::JNL, Mnemonic::JLE, Mnemonic::JNLE,
            };
            return jcc[op - 0x80];
        }

        // SETcc (90-9F)
        if (op >= 0x90 && op <= 0x9F) {
            static constexpr Mnemonic setcc[16] = {
                Mnemonic::SETO, Mnemonic::SETNO, Mnemonic::SETB, Mnemonic::SETNB, Mnemonic::SETZ, Mnemonic::SETNZ, Mnemonic::SETBE, Mnemonic::SETNBE,
                Mnemonic::SETS, Mnemonic::SETNS, Mnemonic::SETP, Mnemonic::SETNP, Mnemonic::SETL, Mnemonic::SETNL, Mnemonic::SETLE, Mnemonic::SETNLE,
            };
            return setcc[op - 0x90];
        }

        switch (op) {
        case 0xA0: return Mnemonic::PUSH; // PUSH FS
        case 0xA1: return Mnemonic::POP;  // POP FS
        case 0xA2: return Mnemonic::CPUID;
        case 0xA3: return Mnemonic::BT;
        case 0xA4: return Mnemonic::SHLD;
        case 0xA5: return Mnemonic::SHLD;
        case 0xA8: return Mnemonic::PUSH; // PUSH GS
        case 0xA9: return Mnemonic::POP;  // POP GS
        case 0xAB: return Mnemonic::BTS;
        case 0xAC: return Mnemonic::SHRD;
        case 0xAD: return Mnemonic::SHRD;
        case 0xAE: {
            // Group 15: FXSAVE/FXRSTOR/LDMXCSR/STMXCSR/XSAVE/XRSTOR/CLFLUSH/LFENCE/MFENCE/SFENCE
            uint8_t mod = ModRM_Mod(ctx.modrm);
            if (mod == kMod_Register) {
                switch (ext) {
                case 5: return Mnemonic::LFENCE;
                case 6: return Mnemonic::MFENCE;
                case 7: return Mnemonic::SFENCE;
                default: return Mnemonic::UNKNOWN;
                }
            }
            switch (ext) {
            case 0: return Mnemonic::FXSAVE;
            case 1: return Mnemonic::FXRSTOR;
            case 2: return Mnemonic::LDMXCSR;
            case 3: return Mnemonic::STMXCSR;
            case 4: return Mnemonic::XSAVE;
            case 5: return Mnemonic::XRSTOR;
            case 7: return Mnemonic::CLFLUSH;
            default: return Mnemonic::UNKNOWN;
            }
        }
        case 0xAF: return Mnemonic::IMUL;
        default: break;
        }

        switch (op) {
        case 0xB0: return Mnemonic::CMPXCHG;
        case 0xB1: return Mnemonic::CMPXCHG;
        case 0xB6: return Mnemonic::MOVZX;
        case 0xB7: return Mnemonic::MOVZX;
        case 0xBA: {
            switch (ext) {
            case 4: return Mnemonic::BT;
            case 5: return Mnemonic::BTS;
            case 6: return Mnemonic::BTR;
            case 7: return Mnemonic::BTC;
            default: return Mnemonic::UNKNOWN;
            }
        }
        case 0xBB: return Mnemonic::BTC;
        case 0xBC:
            if (ctx.hasRep) return Mnemonic::TZCNT;
            return Mnemonic::BSF;
        case 0xBD:
            if (ctx.hasRep) return Mnemonic::LZCNT;
            return Mnemonic::BSR;
        case 0xBE: return Mnemonic::MOVSX;
        case 0xBF: return Mnemonic::MOVSX;
        default: break;
        }

        switch (op) {
        case 0xC0: return Mnemonic::XADD;
        case 0xC1: return Mnemonic::XADD;
        case 0xC2:
            if (ctx.hasRepNE) return Mnemonic::CMPSD_CMP;
            if (ctx.hasRep) return Mnemonic::CMPSS;
            if (ctx.hasOpSizeOverride) return Mnemonic::CMPPD;
            return Mnemonic::CMPPS;
        case 0xC3: return Mnemonic::MOVNTI;
        case 0xC4: return Mnemonic::PINSRW;
        case 0xC5: return Mnemonic::PEXTRW;
        case 0xC6:
            return ctx.hasOpSizeOverride ? Mnemonic::SHUFPD : Mnemonic::SHUFPS;
        case 0xC7: {
            if (ext == 1) {
                return ctx.rexW ? Mnemonic::CMPXCHG16B : Mnemonic::CMPXCHG8B;
            }
            return Mnemonic::UNKNOWN;
        }
        default: break;
        }

        // BSWAP (C8-CF)
        if (op >= 0xC8 && op <= 0xCF) return Mnemonic::BSWAP;

        // SSE packed (D0-FF)
        switch (op) {
        case 0xD0:
            if (ctx.hasOpSizeOverride) return Mnemonic::ADDSUBPD;
            if (ctx.hasRepNE) return Mnemonic::ADDSUBPS;
            return Mnemonic::UNKNOWN;
        case 0xD1: return Mnemonic::PSRLW;
        case 0xD2: return Mnemonic::PSRLD;
        case 0xD3: return Mnemonic::PSRLQ;
        case 0xD4: return Mnemonic::PADDQ;
        case 0xD5: return Mnemonic::PMULLW;
        case 0xD6:
            if (ctx.hasOpSizeOverride) return Mnemonic::MOVQ_SSE;
            return Mnemonic::UNKNOWN;
        case 0xD7: return Mnemonic::PMOVMSKB;
        case 0xD8: return Mnemonic::PSUBUSB;
        case 0xD9: return Mnemonic::PSUBUSW;
        case 0xDA: return Mnemonic::PMINUB;
        case 0xDB: return Mnemonic::PAND;
        case 0xDC: return Mnemonic::PADDUSB;
        case 0xDD: return Mnemonic::PADDUSW;
        case 0xDE: return Mnemonic::PMAXUB;
        case 0xDF: return Mnemonic::PANDN;
        case 0xE0: return Mnemonic::PAVGB;
        case 0xE1: return Mnemonic::PSRAW;
        case 0xE2: return Mnemonic::PSRAD;
        case 0xE3: return Mnemonic::PAVGW;
        case 0xE4: return Mnemonic::PMULHUW;
        case 0xE5: return Mnemonic::PMULHW;
        case 0xE6:
            if (ctx.hasOpSizeOverride) return Mnemonic::CVTTPD2DQ;
            if (ctx.hasRepNE) return Mnemonic::CVTPD2DQ;
            if (ctx.hasRep) return Mnemonic::CVTDQ2PD;
            return Mnemonic::UNKNOWN;
        case 0xE7:
            if (ctx.hasOpSizeOverride) return Mnemonic::MOVNTDQ;
            return Mnemonic::UNKNOWN; // MOVNTQ
        case 0xE8: return Mnemonic::PSUBSB;
        case 0xE9: return Mnemonic::PSUBSW;
        case 0xEA: return Mnemonic::PMINSW;
        case 0xEB: return Mnemonic::POR;
        case 0xEC: return Mnemonic::PADDSB;
        case 0xED: return Mnemonic::PADDSW;
        case 0xEE: return Mnemonic::PMAXSW;
        case 0xEF: return Mnemonic::PXOR;
        case 0xF0:
            if (ctx.hasRepNE) return Mnemonic::LDDQU;
            return Mnemonic::UNKNOWN;
        case 0xF1: return Mnemonic::PSLLW;
        case 0xF2: return Mnemonic::PSLLD;
        case 0xF3: return Mnemonic::PSLLQ;
        case 0xF4: return Mnemonic::PMULUDQ;
        case 0xF5: return Mnemonic::PMADDWD;
        case 0xF6: return Mnemonic::PSADBW;
        case 0xF7:
            if (ctx.hasOpSizeOverride) return Mnemonic::MASKMOVDQU;
            return Mnemonic::UNKNOWN; // MASKMOVQ
        case 0xF8: return Mnemonic::PSUBB;
        case 0xF9: return Mnemonic::PSUBW;
        case 0xFA: return Mnemonic::PSUBD;
        case 0xFB: return Mnemonic::PSUBQ;
        case 0xFC: return Mnemonic::PADDB;
        case 0xFD: return Mnemonic::PADDW;
        case 0xFE: return Mnemonic::PADDD;
        default: return Mnemonic::UNKNOWN;
        }
    } // end map==1

    // ---- 3-byte opcode map 0F38 (map==2) ----
    if (map == 2) {
        switch (op) {
        case 0x00: return Mnemonic::PSHUFB;
        case 0x01: return Mnemonic::PHADDW;
        case 0x02: return Mnemonic::PHADDD;
        case 0x03: return Mnemonic::PHADDSW;
        case 0x04: return Mnemonic::PMADDUBSW;
        case 0x05: return Mnemonic::PHSUBW;
        case 0x06: return Mnemonic::PHSUBD;
        case 0x07: return Mnemonic::PHSUBSW;
        case 0x08: return Mnemonic::PSIGNB;
        case 0x09: return Mnemonic::PSIGNW;
        case 0x0A: return Mnemonic::PSIGND;
        case 0x0B: return Mnemonic::PMULHRSW;
        case 0x10: return Mnemonic::PBLENDVB;
        case 0x14: return Mnemonic::BLENDVPS;
        case 0x15: return Mnemonic::BLENDVPD;
        case 0x17: return Mnemonic::PTEST;
        case 0x1C: return Mnemonic::PABSB;
        case 0x1D: return Mnemonic::PABSW;
        case 0x1E: return Mnemonic::PABSD;
        case 0x20: return Mnemonic::PMOVSXBW;
        case 0x21: return Mnemonic::PMOVSXBD;
        case 0x22: return Mnemonic::PMOVSXBQ;
        case 0x23: return Mnemonic::PMOVSXWD;
        case 0x24: return Mnemonic::PMOVSXWQ;
        case 0x25: return Mnemonic::PMOVSXDQ;
        case 0x28: return Mnemonic::PMULDQ;
        case 0x29: return Mnemonic::PCMPEQQ;
        case 0x2A: return Mnemonic::MOVNTDQA;
        case 0x2B: return Mnemonic::PACKUSDW;
        case 0x30: return Mnemonic::PMOVZXBW;
        case 0x31: return Mnemonic::PMOVZXBD;
        case 0x32: return Mnemonic::PMOVZXBQ;
        case 0x33: return Mnemonic::PMOVZXWD;
        case 0x34: return Mnemonic::PMOVZXWQ;
        case 0x35: return Mnemonic::PMOVZXDQ;
        case 0x37: return Mnemonic::PCMPGTQ;
        case 0x38: return Mnemonic::PMINSB;
        case 0x39: return Mnemonic::PMINSD;
        case 0x3A: return Mnemonic::PMINUW;
        case 0x3B: return Mnemonic::PMINUD;
        case 0x3C: return Mnemonic::PMAXSB;
        case 0x3D: return Mnemonic::PMAXSD;
        case 0x3E: return Mnemonic::PMAXUW;
        case 0x3F: return Mnemonic::PMAXUD;
        case 0x40: return Mnemonic::PMULLD;
        case 0x41: return Mnemonic::PHMINPOSUW;
        case 0xF0:
            if (ctx.hasRepNE) return Mnemonic::CRC32_INST;
            return Mnemonic::MOVBE;
        case 0xF1:
            if (ctx.hasRepNE) return Mnemonic::CRC32_INST;
            return Mnemonic::MOVBE;
        case 0xF6:
            if (ctx.hasOpSizeOverride) return Mnemonic::ADCX;
            if (ctx.hasRep) return Mnemonic::ADOX;
            return Mnemonic::UNKNOWN;
        default: return Mnemonic::UNKNOWN;
        }
    }

    // ---- 3-byte opcode map 0F3A (map==3) ----
    if (map == 3) {
        switch (op) {
        case 0x08: return Mnemonic::ROUNDPS;
        case 0x09: return Mnemonic::ROUNDPD;
        case 0x0A: return Mnemonic::ROUNDSS;
        case 0x0B: return Mnemonic::ROUNDSD;
        case 0x0C: return Mnemonic::BLENDPS;
        case 0x0D: return Mnemonic::BLENDPD;
        case 0x0E: return Mnemonic::PBLENDW;
        case 0x0F: return Mnemonic::PALIGNR;
        case 0x14: return Mnemonic::PEXTRB;
        case 0x15: return Mnemonic::PEXTRW;
        case 0x16:
            return ctx.rexW ? Mnemonic::PEXTRQ : Mnemonic::PEXTRD;
        case 0x17: return Mnemonic::EXTRACTPS;
        case 0x20: return Mnemonic::PINSRB;
        case 0x21: return Mnemonic::INSERTPS;
        case 0x22:
            return ctx.rexW ? Mnemonic::PINSRQ : Mnemonic::PINSRD;
        case 0x40: return Mnemonic::DPPS;
        case 0x41: return Mnemonic::DPPD;
        case 0x42: return Mnemonic::MPSADBW;
        case 0x44: return Mnemonic::PCLMULQDQ;
        case 0x60: return Mnemonic::PCMPESTRM;
        case 0x61: return Mnemonic::PCMPESTRI;
        case 0x62: return Mnemonic::PCMPISTRM;
        case 0x63: return Mnemonic::PCMPISTRI;
        default: return Mnemonic::UNKNOWN;
        }
    }

    return Mnemonic::UNKNOWN;
}

// ============================================================================
// ResolveFPUMnemonic - decode x87 FPU mnemonics (D8-DF)
// ============================================================================



namespace {

Mnemonic ResolveFPUMnemonicImpl(uint8_t primaryOp, uint8_t modrm) noexcept {
    uint8_t mod = ModRM_Mod(modrm);
    uint8_t ext = ModRM_Reg(modrm);
    bool isReg  = (mod == kMod_Register);

    switch (primaryOp) {
    // ---- D8 ----
    case 0xD8: {
        static constexpr Mnemonic d8[8] = {
            Mnemonic::FADD, Mnemonic::FMUL, Mnemonic::FCOM, Mnemonic::FCOMP,
            Mnemonic::FSUB, Mnemonic::FSUBR, Mnemonic::FDIV, Mnemonic::FDIVR,
        };
        return d8[ext];
    }

    // ---- D9 ----
    case 0xD9: {
        if (!isReg) {
            switch (ext) {
            case 0: return Mnemonic::FLD;
            case 2: return Mnemonic::FST;
            case 3: return Mnemonic::FSTP;
            case 4: return Mnemonic::FLDENV;
            case 5: return Mnemonic::FLDCW;
            case 6: return Mnemonic::FNSTENV;
            case 7: return Mnemonic::FNSTCW;
            default: return Mnemonic::UNKNOWN;
            }
        }
        if (ext == 0) return Mnemonic::FLD;
        if (ext == 1) return Mnemonic::FXCH;
        if (modrm == 0xD0) return Mnemonic::FNOP;
        // E0-EF range
        switch (modrm) {
        case 0xE0: return Mnemonic::FCHS;
        case 0xE1: return Mnemonic::FABS;
        case 0xE4: return Mnemonic::UNKNOWN; // FTST
        case 0xE5: return Mnemonic::UNKNOWN; // FXAM
        case 0xE8: return Mnemonic::FLD1;
        case 0xE9: return Mnemonic::FLDL2T;
        case 0xEA: return Mnemonic::FLDL2E;
        case 0xEB: return Mnemonic::FLDPI;
        case 0xEC: return Mnemonic::FLDLN2;
        case 0xED: return Mnemonic::FLDLG2;
        case 0xEE: return Mnemonic::FLDZ;
        case 0xF0: return Mnemonic::F2XM1;
        case 0xF1: return Mnemonic::FYL2X;
        case 0xF2: return Mnemonic::FPTAN;
        case 0xF3: return Mnemonic::FPATAN;
        case 0xF4: return Mnemonic::FXTRACT;
        case 0xF5: return Mnemonic::FPREM1;
        case 0xF6: return Mnemonic::FDECSTP;
        case 0xF7: return Mnemonic::FINCSTP;
        case 0xF8: return Mnemonic::FPREM;
        case 0xF9: return Mnemonic::FYL2XP1;
        case 0xFA: return Mnemonic::FSQRT;
        case 0xFB: return Mnemonic::FSINCOS;
        case 0xFC: return Mnemonic::FRNDINT;
        case 0xFD: return Mnemonic::FSCALE;
        case 0xFE: return Mnemonic::FSIN;
        case 0xFF: return Mnemonic::FCOS;
        default: return Mnemonic::UNKNOWN;
        }
    }

    // ---- DA ----
    case 0xDA: {
        if (!isReg) {
            static constexpr Mnemonic da_mem[8] = {
                Mnemonic::FIADD, Mnemonic::FIMUL, Mnemonic::FICOM, Mnemonic::FICOMP,
                Mnemonic::FISUB, Mnemonic::FISUBR, Mnemonic::FIDIV, Mnemonic::FIDIVR,
            };
            return da_mem[ext];
        }
        switch (ext) {
        case 0: return Mnemonic::UNKNOWN; // FCMOVB
        case 1: return Mnemonic::UNKNOWN; // FCMOVE
        case 2: return Mnemonic::UNKNOWN; // FCMOVBE
        case 3: return Mnemonic::UNKNOWN; // FCMOVU
        default: break;
        }
        if (modrm == 0xE9) return Mnemonic::FUCOMPP;
        return Mnemonic::UNKNOWN;
    }

    // ---- DB ----
    case 0xDB: {
        if (!isReg) {
            switch (ext) {
            case 0: return Mnemonic::FILD;
            case 1: return Mnemonic::UNKNOWN; // FISTTP
            case 2: return Mnemonic::FIST;
            case 3: return Mnemonic::FISTP;
            case 5: return Mnemonic::FLD;  // 80-bit extended
            case 7: return Mnemonic::FSTP; // 80-bit extended
            default: return Mnemonic::UNKNOWN;
            }
        }
        switch (ext) {
        case 0: return Mnemonic::UNKNOWN; // FCMOVNB
        case 1: return Mnemonic::UNKNOWN; // FCMOVNE
        case 2: return Mnemonic::UNKNOWN; // FCMOVNBE
        case 3: return Mnemonic::UNKNOWN; // FCMOVNU
        case 5: return Mnemonic::FUCOMI;
        case 6: return Mnemonic::FCOMI;
        default: break;
        }
        if (modrm == 0xE2) return Mnemonic::FNCLEX;
        if (modrm == 0xE3) return Mnemonic::FNINIT;
        return Mnemonic::UNKNOWN;
    }

    // ---- DC ----
    case 0xDC: {
        static constexpr Mnemonic dc[8] = {
            Mnemonic::FADD, Mnemonic::FMUL, Mnemonic::FCOM, Mnemonic::FCOMP,
            Mnemonic::FSUB, Mnemonic::FSUBR, Mnemonic::FDIV, Mnemonic::FDIVR,
        };
        if (!isReg) return dc[ext];
        // Register forms: reversed operand order for some
        switch (ext) {
        case 0: return Mnemonic::FADD;
        case 1: return Mnemonic::FMUL;
        case 4: return Mnemonic::FSUBR; // operand reversal
        case 5: return Mnemonic::FSUB;
        case 6: return Mnemonic::FDIVR;
        case 7: return Mnemonic::FDIV;
        default: return Mnemonic::UNKNOWN;
        }
    }

    // ---- DD ----
    case 0xDD: {
        if (!isReg) {
            switch (ext) {
            case 0: return Mnemonic::FLD;
            case 1: return Mnemonic::UNKNOWN; // FISTTP (64-bit)
            case 2: return Mnemonic::FST;
            case 3: return Mnemonic::FSTP;
            case 4: return Mnemonic::FRSTOR;
            case 6: return Mnemonic::FNSAVE;
            case 7: return Mnemonic::FNSTSW;
            default: return Mnemonic::UNKNOWN;
            }
        }
        switch (ext) {
        case 0: return Mnemonic::FFREE;
        case 2: return Mnemonic::FST;
        case 3: return Mnemonic::FSTP;
        case 4: return Mnemonic::FUCOM;
        case 5: return Mnemonic::FUCOMP;
        default: return Mnemonic::UNKNOWN;
        }
    }

    // ---- DE ----
    case 0xDE: {
        if (!isReg) {
            static constexpr Mnemonic de_mem[8] = {
                Mnemonic::FIADD, Mnemonic::FIMUL, Mnemonic::FICOM, Mnemonic::FICOMP,
                Mnemonic::FISUB, Mnemonic::FISUBR, Mnemonic::FIDIV, Mnemonic::FIDIVR,
            };
            return de_mem[ext];
        }
        if (modrm == 0xD9) return Mnemonic::FCOMPP;
        switch (ext) {
        case 0: return Mnemonic::FADDP;
        case 1: return Mnemonic::FMULP;
        case 4: return Mnemonic::FSUBRP;
        case 5: return Mnemonic::FSUBP;
        case 6: return Mnemonic::FDIVRP;
        case 7: return Mnemonic::FDIVP;
        default: return Mnemonic::UNKNOWN;
        }
    }

    // ---- DF ----
    case 0xDF: {
        if (!isReg) {
            switch (ext) {
            case 0: return Mnemonic::FILD;
            case 1: return Mnemonic::UNKNOWN; // FISTTP (word)
            case 2: return Mnemonic::FIST;
            case 3: return Mnemonic::FISTP;
            case 4: return Mnemonic::UNKNOWN; // FBLD
            case 5: return Mnemonic::FILD;    // 64-bit
            case 6: return Mnemonic::UNKNOWN; // FBSTP
            case 7: return Mnemonic::FISTP;   // 64-bit
            default: return Mnemonic::UNKNOWN;
            }
        }
        if (modrm == 0xE0) return Mnemonic::FNSTSW; // FNSTSW AX
        if (ext == 5) return Mnemonic::FUCOMIP;
        if (ext == 6) return Mnemonic::FCOMIP;
        return Mnemonic::UNKNOWN;
    }

    default: return Mnemonic::UNKNOWN;
    }
}

} // anonymous namespace

// ============================================================================
// ResolveCategory
// ============================================================================

InstructionCategory Decoder::ResolveCategory(Mnemonic mnemonic) const noexcept {
    switch (mnemonic) {
    case Mnemonic::ADD: case Mnemonic::ADC: case Mnemonic::SUB: case Mnemonic::SBB:
    case Mnemonic::INC: case Mnemonic::DEC: case Mnemonic::NEG:
    case Mnemonic::MUL: case Mnemonic::IMUL: case Mnemonic::DIV: case Mnemonic::IDIV:
        return InstructionCategory::ARITHMETIC;

    case Mnemonic::AND: case Mnemonic::OR: case Mnemonic::XOR: case Mnemonic::NOT:
    case Mnemonic::TEST:
        return InstructionCategory::LOGIC;

    case Mnemonic::SHL: case Mnemonic::SHR: case Mnemonic::SAR: case Mnemonic::SAL:
    case Mnemonic::ROL: case Mnemonic::ROR: case Mnemonic::RCL: case Mnemonic::RCR:
    case Mnemonic::SHLD: case Mnemonic::SHRD:
        return InstructionCategory::SHIFT_ROTATE;

    case Mnemonic::MOV: case Mnemonic::MOVZX: case Mnemonic::MOVSX: case Mnemonic::MOVSXD:
    case Mnemonic::LEA: case Mnemonic::XCHG: case Mnemonic::BSWAP: case Mnemonic::MOVBE:
    case Mnemonic::CMC: case Mnemonic::MOVD_SSE: case Mnemonic::MOVQ_SSE:
        return InstructionCategory::DATA_TRANSFER;

    case Mnemonic::JMP: case Mnemonic::CALL: case Mnemonic::RET: case Mnemonic::RETF:
    case Mnemonic::JO: case Mnemonic::JNO: case Mnemonic::JB: case Mnemonic::JNB:
    case Mnemonic::JZ: case Mnemonic::JNZ: case Mnemonic::JBE: case Mnemonic::JNBE:
    case Mnemonic::JS: case Mnemonic::JNS: case Mnemonic::JP: case Mnemonic::JNP:
    case Mnemonic::JL: case Mnemonic::JNL: case Mnemonic::JLE: case Mnemonic::JNLE:
    case Mnemonic::JCXZ: case Mnemonic::JECXZ: case Mnemonic::JRCXZ:
    case Mnemonic::LOOP: case Mnemonic::LOOPE: case Mnemonic::LOOPNE:
        return InstructionCategory::CONTROL_FLOW;

    case Mnemonic::PUSH: case Mnemonic::POP: case Mnemonic::PUSHA: case Mnemonic::POPA:
    case Mnemonic::ENTER: case Mnemonic::LEAVE:
    case Mnemonic::PUSHF: case Mnemonic::PUSHFQ: case Mnemonic::POPF: case Mnemonic::POPFQ:
        return InstructionCategory::STACK;

    case Mnemonic::MOVSB: case Mnemonic::MOVSW: case Mnemonic::MOVSD_STR: case Mnemonic::MOVSQ:
    case Mnemonic::CMPSB: case Mnemonic::CMPSW: case Mnemonic::CMPSD_STR: case Mnemonic::CMPSQ:
    case Mnemonic::STOSB: case Mnemonic::STOSW: case Mnemonic::STOSD: case Mnemonic::STOSQ:
    case Mnemonic::LODSB: case Mnemonic::LODSW: case Mnemonic::LODSD: case Mnemonic::LODSQ:
    case Mnemonic::SCASB: case Mnemonic::SCASW: case Mnemonic::SCASD: case Mnemonic::SCASQ:
    case Mnemonic::INS: case Mnemonic::OUTS:
        return InstructionCategory::STRING;

    case Mnemonic::CLC: case Mnemonic::STC: case Mnemonic::CLI: case Mnemonic::STI:
    case Mnemonic::CLD: case Mnemonic::STD: case Mnemonic::SAHF: case Mnemonic::LAHF:
        return InstructionCategory::FLAG;

    case Mnemonic::IN: case Mnemonic::OUT:
        return InstructionCategory::IO;

    case Mnemonic::INT: case Mnemonic::INT1: case Mnemonic::INT3: case Mnemonic::INTO:
    case Mnemonic::IRET: case Mnemonic::IRETD: case Mnemonic::IRETQ:
        return InstructionCategory::INTERRUPT;

    case Mnemonic::SYSCALL: case Mnemonic::SYSENTER: case Mnemonic::SYSEXIT:
    case Mnemonic::SYSRET: case Mnemonic::CPUID: case Mnemonic::RDTSC: case Mnemonic::RDTSCP:
    case Mnemonic::RDMSR: case Mnemonic::WRMSR: case Mnemonic::RDPMC:
    case Mnemonic::SGDT: case Mnemonic::SIDT: case Mnemonic::LGDT: case Mnemonic::LIDT:
    case Mnemonic::SLDT: case Mnemonic::STR: case Mnemonic::LLDT: case Mnemonic::LTR:
    case Mnemonic::SMSW: case Mnemonic::LMSW: case Mnemonic::INVLPG: case Mnemonic::INVD:
    case Mnemonic::WBINVD: case Mnemonic::CLTS: case Mnemonic::SWAPGS:
    case Mnemonic::HLT: case Mnemonic::UD2:
    case Mnemonic::VERR: case Mnemonic::VERW:
        return InstructionCategory::SYSTEM;

    case Mnemonic::NOP: case Mnemonic::PAUSE:
        return InstructionCategory::NOP;

    case Mnemonic::CBW: case Mnemonic::CWDE: case Mnemonic::CDQE:
    case Mnemonic::CWD: case Mnemonic::CDQ: case Mnemonic::CQO:
        return InstructionCategory::CONVERT;

    case Mnemonic::CMPXCHG: case Mnemonic::CMPXCHG8B: case Mnemonic::CMPXCHG16B:
    case Mnemonic::XADD:
    case Mnemonic::BT: case Mnemonic::BTS: case Mnemonic::BTR: case Mnemonic::BTC:
    case Mnemonic::BSF: case Mnemonic::BSR: case Mnemonic::TZCNT: case Mnemonic::LZCNT:
    case Mnemonic::POPCNT:
        return InstructionCategory::BINARY;

    // FPU
    case Mnemonic::FADD: case Mnemonic::FMUL: case Mnemonic::FCOM: case Mnemonic::FCOMP:
    case Mnemonic::FSUB: case Mnemonic::FSUBR: case Mnemonic::FDIV: case Mnemonic::FDIVR:
    case Mnemonic::FLD: case Mnemonic::FST: case Mnemonic::FSTP:
    case Mnemonic::FILD: case Mnemonic::FIST: case Mnemonic::FISTP:
    case Mnemonic::FIADD: case Mnemonic::FIMUL: case Mnemonic::FICOM: case Mnemonic::FICOMP:
    case Mnemonic::FISUB: case Mnemonic::FISUBR: case Mnemonic::FIDIV: case Mnemonic::FIDIVR:
    case Mnemonic::FADDP: case Mnemonic::FMULP: case Mnemonic::FCOMPP:
    case Mnemonic::FSUBP: case Mnemonic::FSUBRP: case Mnemonic::FDIVP: case Mnemonic::FDIVRP:
    case Mnemonic::FUCOM: case Mnemonic::FUCOMP: case Mnemonic::FUCOMPP:
    case Mnemonic::FUCOMI: case Mnemonic::FUCOMIP: case Mnemonic::FCOMI: case Mnemonic::FCOMIP:
    case Mnemonic::FXCH: case Mnemonic::FFREE: case Mnemonic::FNOP:
    case Mnemonic::FCHS: case Mnemonic::FABS: case Mnemonic::FSQRT:
    case Mnemonic::FSIN: case Mnemonic::FCOS: case Mnemonic::FSINCOS:
    case Mnemonic::FPTAN: case Mnemonic::FPATAN: case Mnemonic::F2XM1:
    case Mnemonic::FYL2X: case Mnemonic::FYL2XP1: case Mnemonic::FXTRACT:
    case Mnemonic::FPREM: case Mnemonic::FPREM1: case Mnemonic::FRNDINT: case Mnemonic::FSCALE:
    case Mnemonic::FDECSTP: case Mnemonic::FINCSTP:
    case Mnemonic::FLD1: case Mnemonic::FLDZ: case Mnemonic::FLDPI:
    case Mnemonic::FLDL2E: case Mnemonic::FLDL2T: case Mnemonic::FLDLN2: case Mnemonic::FLDLG2:
    case Mnemonic::FLDENV: case Mnemonic::FLDCW: case Mnemonic::FNSTENV: case Mnemonic::FNSTCW:
    case Mnemonic::FNSTSW: case Mnemonic::FRSTOR: case Mnemonic::FNSAVE:
    case Mnemonic::FWAIT: case Mnemonic::FNCLEX: case Mnemonic::FNINIT:
    case Mnemonic::FXSAVE: case Mnemonic::FXRSTOR:
        return InstructionCategory::FPU;

    // SSE
    case Mnemonic::MOVUPS: case Mnemonic::MOVSS: case Mnemonic::MOVUPD: case Mnemonic::MOVSD_SSE:
    case Mnemonic::MOVAPS: case Mnemonic::MOVAPD: case Mnemonic::MOVDQA: case Mnemonic::MOVDQU:
    case Mnemonic::MOVLPS: case Mnemonic::MOVLPD: case Mnemonic::MOVHPS: case Mnemonic::MOVHPD:
    case Mnemonic::MOVNTPS: case Mnemonic::MOVNTPD: case Mnemonic::MOVNTDQ:
    case Mnemonic::MOVMSKPS: case Mnemonic::MOVMSKPD:
    case Mnemonic::ADDPS: case Mnemonic::ADDSS: case Mnemonic::ADDPD: case Mnemonic::ADDSD:
    case Mnemonic::SUBPS: case Mnemonic::SUBSS: case Mnemonic::SUBPD: case Mnemonic::SUBSD:
    case Mnemonic::MULPS: case Mnemonic::MULSS: case Mnemonic::MULPD: case Mnemonic::MULSD:
    case Mnemonic::DIVPS: case Mnemonic::DIVSS: case Mnemonic::DIVPD: case Mnemonic::DIVSD:
    case Mnemonic::MINPS: case Mnemonic::MINSS: case Mnemonic::MINPD: case Mnemonic::MINSD:
    case Mnemonic::MAXPS: case Mnemonic::MAXSS: case Mnemonic::MAXPD: case Mnemonic::MAXSD:
    case Mnemonic::SQRTPS: case Mnemonic::SQRTSS: case Mnemonic::SQRTPD: case Mnemonic::SQRTSD:
    case Mnemonic::RSQRTPS: case Mnemonic::RSQRTSS: case Mnemonic::RCPPS: case Mnemonic::RCPSS:
    case Mnemonic::ANDPS: case Mnemonic::ANDPD: case Mnemonic::ANDNPS: case Mnemonic::ANDNPD:
    case Mnemonic::ORPS: case Mnemonic::ORPD: case Mnemonic::XORPS: case Mnemonic::XORPD:
    case Mnemonic::UNPCKLPS: case Mnemonic::UNPCKHPS:
    case Mnemonic::UNPCKLPD: case Mnemonic::UNPCKHPD:
    case Mnemonic::SHUFPS: case Mnemonic::SHUFPD:
    case Mnemonic::CMPPS: case Mnemonic::CMPSS: case Mnemonic::CMPPD: case Mnemonic::CMPSD_CMP:
    case Mnemonic::UCOMISS: case Mnemonic::UCOMISD: case Mnemonic::COMISS: case Mnemonic::COMISD:
    case Mnemonic::CVTPI2PS: case Mnemonic::CVTSI2SS:
    case Mnemonic::CVTPI2PD: case Mnemonic::CVTSI2SD:
    case Mnemonic::CVTTPS2PI: case Mnemonic::CVTTSS2SI:
    case Mnemonic::CVTTPD2PI: case Mnemonic::CVTTSD2SI:
    case Mnemonic::CVTPS2PI: case Mnemonic::CVTSS2SI:
    case Mnemonic::CVTPD2PI: case Mnemonic::CVTSD2SI:
    case Mnemonic::CVTPS2PD: case Mnemonic::CVTSS2SD:
    case Mnemonic::CVTPD2PS: case Mnemonic::CVTSD2SS:
    case Mnemonic::CVTDQ2PS: case Mnemonic::CVTTPS2DQ: case Mnemonic::CVTPS2DQ:
    case Mnemonic::CVTTPD2DQ: case Mnemonic::CVTPD2DQ: case Mnemonic::CVTDQ2PD:
    case Mnemonic::PUNPCKLBW: case Mnemonic::PUNPCKLWD: case Mnemonic::PUNPCKLDQ:
    case Mnemonic::PUNPCKHBW: case Mnemonic::PUNPCKHWD: case Mnemonic::PUNPCKHDQ:
    case Mnemonic::PUNPCKLQDQ: case Mnemonic::PUNPCKHQDQ:
    case Mnemonic::PACKSSWB: case Mnemonic::PACKSSDW: case Mnemonic::PACKUSWB:
    case Mnemonic::PCMPGTB: case Mnemonic::PCMPGTW: case Mnemonic::PCMPGTD:
    case Mnemonic::PCMPEQB: case Mnemonic::PCMPEQW: case Mnemonic::PCMPEQD:
    case Mnemonic::PADDB: case Mnemonic::PADDW: case Mnemonic::PADDD: case Mnemonic::PADDQ:
    case Mnemonic::PSUBB: case Mnemonic::PSUBW: case Mnemonic::PSUBD: case Mnemonic::PSUBQ:
    case Mnemonic::PMULLW: case Mnemonic::PMULHUW: case Mnemonic::PMULHW: case Mnemonic::PMULUDQ:
    case Mnemonic::PMADDWD: case Mnemonic::PSADBW:
    case Mnemonic::PSRLW: case Mnemonic::PSRLD: case Mnemonic::PSRLQ:
    case Mnemonic::PSRAW: case Mnemonic::PSRAD:
    case Mnemonic::PSLLW: case Mnemonic::PSLLD: case Mnemonic::PSLLQ:
    case Mnemonic::PAND: case Mnemonic::PANDN: case Mnemonic::POR: case Mnemonic::PXOR:
    case Mnemonic::PADDSB: case Mnemonic::PADDSW: case Mnemonic::PADDUSB: case Mnemonic::PADDUSW:
    case Mnemonic::PSUBSB: case Mnemonic::PSUBSW: case Mnemonic::PSUBUSB: case Mnemonic::PSUBUSW:
    case Mnemonic::PMINUB: case Mnemonic::PMINSW: case Mnemonic::PMAXUB: case Mnemonic::PMAXSW:
    case Mnemonic::PAVGB: case Mnemonic::PAVGW:
    case Mnemonic::PMOVMSKB: case Mnemonic::EMMS:
    case Mnemonic::PINSRW: case Mnemonic::PEXTRW:
    case Mnemonic::PSHUFD: case Mnemonic::PSHUFHW: case Mnemonic::PSHUFLW:
    case Mnemonic::MASKMOVDQU: case Mnemonic::LDDQU:
    case Mnemonic::ADDSUBPD: case Mnemonic::ADDSUBPS:
    case Mnemonic::HADDPD: case Mnemonic::HADDPS: case Mnemonic::HSUBPD: case Mnemonic::HSUBPS:
    case Mnemonic::MOVNTI: case Mnemonic::MOVDDUP:
    case Mnemonic::PSHUFB: case Mnemonic::PHADDW: case Mnemonic::PHADDD: case Mnemonic::PHADDSW:
    case Mnemonic::PMADDUBSW: case Mnemonic::PHSUBW: case Mnemonic::PHSUBD: case Mnemonic::PHSUBSW:
    case Mnemonic::PSIGNB: case Mnemonic::PSIGNW: case Mnemonic::PSIGND: case Mnemonic::PMULHRSW:
    case Mnemonic::PABSB: case Mnemonic::PABSW: case Mnemonic::PABSD:
    case Mnemonic::PALIGNR:
    case Mnemonic::PBLENDVB: case Mnemonic::BLENDVPS: case Mnemonic::BLENDVPD: case Mnemonic::PTEST:
    case Mnemonic::PMOVSXBW: case Mnemonic::PMOVSXBD: case Mnemonic::PMOVSXBQ:
    case Mnemonic::PMOVSXWD: case Mnemonic::PMOVSXWQ: case Mnemonic::PMOVSXDQ:
    case Mnemonic::PMOVZXBW: case Mnemonic::PMOVZXBD: case Mnemonic::PMOVZXBQ:
    case Mnemonic::PMOVZXWD: case Mnemonic::PMOVZXWQ: case Mnemonic::PMOVZXDQ:
    case Mnemonic::PMULDQ: case Mnemonic::PCMPEQQ: case Mnemonic::MOVNTDQA:
    case Mnemonic::PACKUSDW: case Mnemonic::PCMPGTQ:
    case Mnemonic::PMINSB: case Mnemonic::PMINSD: case Mnemonic::PMINUW: case Mnemonic::PMINUD:
    case Mnemonic::PMAXSB: case Mnemonic::PMAXSD: case Mnemonic::PMAXUW: case Mnemonic::PMAXUD:
    case Mnemonic::PMULLD: case Mnemonic::PHMINPOSUW:
    case Mnemonic::ROUNDPS: case Mnemonic::ROUNDPD: case Mnemonic::ROUNDSS: case Mnemonic::ROUNDSD:
    case Mnemonic::BLENDPS: case Mnemonic::BLENDPD: case Mnemonic::PBLENDW:
    case Mnemonic::PEXTRB: case Mnemonic::PEXTRD: case Mnemonic::PEXTRQ: case Mnemonic::EXTRACTPS:
    case Mnemonic::PINSRB: case Mnemonic::INSERTPS: case Mnemonic::PINSRD: case Mnemonic::PINSRQ:
    case Mnemonic::DPPS: case Mnemonic::DPPD: case Mnemonic::MPSADBW:
    case Mnemonic::PCLMULQDQ:
    case Mnemonic::PCMPESTRM: case Mnemonic::PCMPESTRI:
    case Mnemonic::PCMPISTRM: case Mnemonic::PCMPISTRI:
    case Mnemonic::CRC32_INST:
        return InstructionCategory::SSE;

    case Mnemonic::CMOVO: case Mnemonic::CMOVNO: case Mnemonic::CMOVB: case Mnemonic::CMOVNB:
    case Mnemonic::CMOVZ: case Mnemonic::CMOVNZ: case Mnemonic::CMOVBE: case Mnemonic::CMOVNBE:
    case Mnemonic::CMOVS: case Mnemonic::CMOVNS: case Mnemonic::CMOVP: case Mnemonic::CMOVNP:
    case Mnemonic::CMOVL: case Mnemonic::CMOVNL: case Mnemonic::CMOVLE: case Mnemonic::CMOVNLE:
        return InstructionCategory::DATA_TRANSFER;

    case Mnemonic::SETO: case Mnemonic::SETNO: case Mnemonic::SETB: case Mnemonic::SETNB:
    case Mnemonic::SETZ: case Mnemonic::SETNZ: case Mnemonic::SETBE: case Mnemonic::SETNBE:
    case Mnemonic::SETS: case Mnemonic::SETNS: case Mnemonic::SETP: case Mnemonic::SETNP:
    case Mnemonic::SETL: case Mnemonic::SETNL: case Mnemonic::SETLE: case Mnemonic::SETNLE:
        return InstructionCategory::FLAG;

    case Mnemonic::PREFETCHNTA: case Mnemonic::PREFETCHT0:
    case Mnemonic::PREFETCHT1: case Mnemonic::PREFETCHT2:
    case Mnemonic::LFENCE: case Mnemonic::MFENCE: case Mnemonic::SFENCE:
    case Mnemonic::CLFLUSH:
    case Mnemonic::LDMXCSR: case Mnemonic::STMXCSR:
        return InstructionCategory::SSE;

    case Mnemonic::ADCX: case Mnemonic::ADOX:
        return InstructionCategory::ARITHMETIC;

    default: return InstructionCategory::UNKNOWN;
    }
}

// ============================================================================
// ResolveISAExtension
// ============================================================================

ISAExtension Decoder::ResolveISAExtension(const DecodeContext& ctx) const noexcept {
    if (ctx.hasEVEX) return ISAExtension::AVX512F;
    if (ctx.hasVEX)  return ISAExtension::AVX;
    if (ctx.opcodeMap == 3) return ISAExtension::SSE4_1;
    if (ctx.opcodeMap == 2) {
        uint8_t op = ctx.opcode;
        if (op <= 0x0B) return ISAExtension::SSSE3;
        if (op >= 0x10 && op <= 0x15) return ISAExtension::SSE4_1;
        if (op >= 0x17 && op <= 0x1E) return ISAExtension::SSSE3;
        if (op >= 0x20 && op <= 0x25) return ISAExtension::SSE4_1;
        if (op >= 0x28 && op <= 0x41) return ISAExtension::SSE4_1;
        if (op == 0xF0 || op == 0xF1) {
            if (ctx.hasRepNE) return ISAExtension::SSE4_2;
            return ISAExtension::BASE;
        }
        return ISAExtension::SSE4_1;
    }
    if (ctx.opcodeMap == 1) {
        uint8_t op = ctx.opcode;
        if (op >= 0xD8 && op <= 0xDF) return ISAExtension::FPU;
        if (op >= 0x10 && op <= 0x17) return ISAExtension::SSE;
        if (op >= 0x28 && op <= 0x2F) return ISAExtension::SSE;
        if (op >= 0x50 && op <= 0x5F) return ISAExtension::SSE;
        if (op >= 0x60 && op <= 0x7F) return ISAExtension::SSE2;
        if (op >= 0xC2 && op <= 0xC6) return ISAExtension::SSE;
        if (op >= 0xD0 && op <= 0xFF) return ISAExtension::SSE2;
        return ISAExtension::BASE;
    }
    if (ctx.opcodeMap == 0 && ctx.opcode >= 0xD8 && ctx.opcode <= 0xDF) {
        return ISAExtension::FPU;
    }
    return ISAExtension::BASE;
}

// ============================================================================
// ResolveGPR - map register index + size to Register enum
// ============================================================================

Register Decoder::ResolveGPR(uint8_t index, uint16_t sizeBits, bool hasRex) const noexcept {
    index &= 0x0F;

    if (sizeBits == 64) {
        static constexpr Register r64[16] = {
            Register::RAX, Register::RCX, Register::RDX, Register::RBX,
            Register::RSP, Register::RBP, Register::RSI, Register::RDI,
            Register::R8,  Register::R9,  Register::R10, Register::R11,
            Register::R12, Register::R13, Register::R14, Register::R15,
        };
        return r64[index];
    }
    if (sizeBits == 32) {
        static constexpr Register r32[16] = {
            Register::EAX, Register::ECX, Register::EDX, Register::EBX,
            Register::ESP, Register::EBP, Register::ESI, Register::EDI,
            Register::R8D, Register::R9D, Register::R10D, Register::R11D,
            Register::R12D, Register::R13D, Register::R14D, Register::R15D,
        };
        return r32[index];
    }
    if (sizeBits == 16) {
        static constexpr Register r16[16] = {
            Register::AX,  Register::CX,  Register::DX,  Register::BX,
            Register::SP,  Register::BP,  Register::SI,  Register::DI,
            Register::R8W, Register::R9W, Register::R10W, Register::R11W,
            Register::R12W, Register::R13W, Register::R14W, Register::R15W,
        };
        return r16[index];
    }
    if (sizeBits == 8) {
        if (!hasRex && index >= 4 && index <= 7) {
            static constexpr Register rHigh[4] = {
                Register::AH, Register::CH, Register::DH, Register::BH,
            };
            return rHigh[index - 4];
        }
        static constexpr Register r8[16] = {
            Register::AL,  Register::CL,  Register::DL,  Register::BL,
            Register::SPL, Register::BPL, Register::SIL, Register::DIL,
            Register::R8B, Register::R9B, Register::R10B, Register::R11B,
            Register::R12B, Register::R13B, Register::R14B, Register::R15B,
        };
        return r8[index];
    }
    return Register::NONE;
}

// ============================================================================
// ResolveSegment
// ============================================================================

Register Decoder::ResolveSegment(uint8_t index) const noexcept {
    static constexpr Register segs[6] = {
        Register::ES, Register::CS, Register::SS,
        Register::DS, Register::FS, Register::GS,
    };
    return (index < 6) ? segs[index] : Register::NONE;
}

// ============================================================================
// ResolveSIMD - map index to XMM/YMM/ZMM register
// ============================================================================

Register Decoder::ResolveSIMD(uint8_t index, uint8_t vectorLength) const noexcept {
    index &= 0x1F;
    if (vectorLength == 0) { // 128-bit
        static constexpr Register xmm[32] = {
            Register::XMM0,  Register::XMM1,  Register::XMM2,  Register::XMM3,
            Register::XMM4,  Register::XMM5,  Register::XMM6,  Register::XMM7,
            Register::XMM8,  Register::XMM9,  Register::XMM10, Register::XMM11,
            Register::XMM12, Register::XMM13, Register::XMM14, Register::XMM15,
            Register::XMM16, Register::XMM17, Register::XMM18, Register::XMM19,
            Register::XMM20, Register::XMM21, Register::XMM22, Register::XMM23,
            Register::XMM24, Register::XMM25, Register::XMM26, Register::XMM27,
            Register::XMM28, Register::XMM29, Register::XMM30, Register::XMM31,
        };
        return xmm[index];
    }
    if (vectorLength == 1) { // 256-bit
        static constexpr Register ymm[32] = {
            Register::YMM0,  Register::YMM1,  Register::YMM2,  Register::YMM3,
            Register::YMM4,  Register::YMM5,  Register::YMM6,  Register::YMM7,
            Register::YMM8,  Register::YMM9,  Register::YMM10, Register::YMM11,
            Register::YMM12, Register::YMM13, Register::YMM14, Register::YMM15,
            Register::YMM16, Register::YMM17, Register::YMM18, Register::YMM19,
            Register::YMM20, Register::YMM21, Register::YMM22, Register::YMM23,
            Register::YMM24, Register::YMM25, Register::YMM26, Register::YMM27,
            Register::YMM28, Register::YMM29, Register::YMM30, Register::YMM31,
        };
        return ymm[index];
    }
    if (vectorLength == 2) { // 512-bit
        static constexpr Register zmm[32] = {
            Register::ZMM0,  Register::ZMM1,  Register::ZMM2,  Register::ZMM3,
            Register::ZMM4,  Register::ZMM5,  Register::ZMM6,  Register::ZMM7,
            Register::ZMM8,  Register::ZMM9,  Register::ZMM10, Register::ZMM11,
            Register::ZMM12, Register::ZMM13, Register::ZMM14, Register::ZMM15,
            Register::ZMM16, Register::ZMM17, Register::ZMM18, Register::ZMM19,
            Register::ZMM20, Register::ZMM21, Register::ZMM22, Register::ZMM23,
            Register::ZMM24, Register::ZMM25, Register::ZMM26, Register::ZMM27,
            Register::ZMM28, Register::ZMM29, Register::ZMM30, Register::ZMM31,
        };
        return zmm[index];
    }
    return Register::NONE;
}

// ============================================================================
// DefaultSegment
// ============================================================================

Register Decoder::DefaultSegment(uint8_t baseReg) const noexcept {
    // baseReg is the register index: 4=xSP, 5=xBP
    if (baseReg == 4 || baseReg == 5 || baseReg == 12 || baseReg == 13)
        return Register::SS;
    return Register::DS;
}

// ============================================================================
// Operand builders
// ============================================================================

void Decoder::BuildRegOperand(DecodedOperand& op, Register reg, uint16_t sizeBits) noexcept {
    op.type = OperandType::REGISTER;
    op.size = sizeBits;
    op.reg.value = reg;
}

void Decoder::BuildMemOperand(DecodedOperand& op, const DecodeContext& ctx,
                               int64_t displacement, uint16_t sizeBits) noexcept {
    op.type = OperandType::MEMORY;
    op.size = sizeBits;

    uint8_t mod = ModRM_Mod(ctx.modrm);
    uint8_t rm  = ModRM_RM(ctx.modrm);
    bool is64 = (ctx.effectiveAddressWidth == 64);
    bool is32 = (ctx.effectiveAddressWidth == 32);
    uint16_t addrBits = is64 ? 64 : (is32 ? 32 : 16);

    // Segment override
    if (ctx.hasSegOverride)
        op.mem.segment = ctx.segOverride;

    if (ctx.effectiveAddressWidth == 16) {
        // 16-bit addressing
        static constexpr Register bases16[8] = {
            Register::BX, Register::BX, Register::BP, Register::BP,
            Register::SI, Register::DI, Register::BP, Register::BX,
        };
        static constexpr Register indices16[8] = {
            Register::SI, Register::DI, Register::SI, Register::DI,
            Register::NONE, Register::NONE, Register::NONE, Register::NONE,
        };
        if (mod == kMod_Indirect && rm == 6) {
            // [disp16]
            op.mem.disp.has_displacement = true;
            op.mem.disp.value = displacement;
            if (!ctx.hasSegOverride) op.mem.segment = Register::DS;
        } else {
            op.mem.base = bases16[rm];
            if (indices16[rm] != Register::NONE) {
                op.mem.index = indices16[rm];
                op.mem.scale = 1;
            }
            if (mod == kMod_Disp8 || mod == kMod_Disp32) {
                op.mem.disp.has_displacement = true;
                op.mem.disp.value = displacement;
            }
            if (!ctx.hasSegOverride)
                op.mem.segment = DefaultSegment(rm);
        }
        return;
    }

    // 32/64-bit addressing
    if (!ctx.hasSIB) {
        if (mod == kMod_Indirect && rm == kRM_Disp32) {
            // [disp32] or [RIP+disp32]
            op.mem.disp.has_displacement = true;
            op.mem.disp.value = displacement;
            if (is64) {
                op.mem.base = Register::RIP;
            }
            if (!ctx.hasSegOverride) op.mem.segment = Register::DS;
        } else {
            uint8_t baseIdx = rm;
            if (ctx.rexB) baseIdx |= 0x08;
            op.mem.base = ResolveGPR(baseIdx, addrBits, ctx.hasREX);
            if (mod == kMod_Disp8 || mod == kMod_Disp32) {
                op.mem.disp.has_displacement = true;
                op.mem.disp.value = displacement;
            }
            if (!ctx.hasSegOverride)
                op.mem.segment = DefaultSegment(baseIdx & 0x07);
        }
        return;
    }

    // SIB addressing
    uint8_t sibScale = SIB_Scale(ctx.sib);
    uint8_t sibIndex = SIB_Index(ctx.sib);
    uint8_t sibBase  = SIB_Base(ctx.sib);

    // Base register
    if (sibBase == kSIB_Disp32Base && mod == kMod_Indirect) {
        // No base, disp32 only
        op.mem.disp.has_displacement = true;
        op.mem.disp.value = displacement;
        if (!ctx.hasSegOverride) op.mem.segment = Register::DS;
    } else {
        uint8_t baseIdx = sibBase;
        if (ctx.rexB) baseIdx |= 0x08;
        op.mem.base = ResolveGPR(baseIdx, addrBits, ctx.hasREX);
        if (mod == kMod_Disp8 || mod == kMod_Disp32) {
            op.mem.disp.has_displacement = true;
            op.mem.disp.value = displacement;
        }
        if (!ctx.hasSegOverride)
            op.mem.segment = DefaultSegment(sibBase);
    }

    // Index register (4=no index)
    if (sibIndex != kSIB_NoIndex || ctx.rexX) {
        uint8_t idxReg = sibIndex;
        if (ctx.rexX) idxReg |= 0x08;
        op.mem.index = ResolveGPR(idxReg, addrBits, ctx.hasREX);
        op.mem.scale = kScaleFactors[sibScale];
    }
}

void Decoder::BuildImmOperand(DecodedOperand& op, int64_t value, uint16_t sizeBits,
                               bool isSigned, bool isRelative) noexcept {
    op.type = isRelative ? OperandType::RELATIVE : OperandType::IMMEDIATE;
    op.size = sizeBits;
    op.imm.is_signed = isSigned;
    op.imm.is_relative = isRelative;
    op.imm.value.s = value;
    op.imm.value.u = static_cast<uint64_t>(value);
}

// ============================================================================
// Standard operand pattern decoders
// ============================================================================

void Decoder::DecodeModRMOperands(DecodeContext& ctx,
    DecodedInstruction& inst, DecodedOperand* operands,
    uint16_t regSizeBits, uint16_t rmSizeBits, bool regIsDst) noexcept
{
    uint8_t mod = ModRM_Mod(ctx.modrm);
    uint8_t reg = ModRM_Reg(ctx.modrm);
    uint8_t rm  = ModRM_RM(ctx.modrm);
    if (ctx.rexR) reg |= 0x08;
    if (ctx.rexB) rm  |= 0x08;

    // Reg operand
    DecodedOperand regOp{};
    BuildRegOperand(regOp, ResolveGPR(reg, regSizeBits, ctx.hasREX), regSizeBits);

    // R/M operand
    DecodedOperand rmOp{};
    if (mod == kMod_Register) {
        BuildRegOperand(rmOp, ResolveGPR(rm, rmSizeBits, ctx.hasREX), rmSizeBits);
    } else {
        // Compute displacement from context
        // The displacement was already read; retrieve from the raw bytes
        int64_t disp = 0;
        uint32_t dispOff = 0;
        uint8_t dispSz = 0;

        // Calculate where displacement starts in the buffer
        // It's after prefixes + opcode + modrm + optional SIB
        if (mod == kMod_Disp8) { dispSz = 1; }
        else if (mod == kMod_Disp32) { dispSz = 4; }
        else if (mod == kMod_Indirect) {
            uint8_t rawRm = ModRM_RM(ctx.modrm);
            if (ctx.effectiveAddressWidth == 16 && rawRm == 6) dispSz = 2;
            else if (rawRm == kRM_Disp32) dispSz = 4;
            else if (ctx.hasSIB && SIB_Base(ctx.sib) == kSIB_Disp32Base) dispSz = 4;
        }

        if (dispSz > 0) {
            // Re-read displacement from buffer using computed position
            // Compute displacement position: after prefix + opcode + modrm + optional SIB
            if (ctx.hasSIB) {
                // prefix + opcode + modrm(1) + sib(1) + disp
                dispOff = ctx.offset;
                // The offset points past displacement and immediate
                // We need to figure out where disp was
            }
            // Simpler: re-read from the buffer at the right position
            // Prefix bytes + opcode bytes + modrm(1) + sib(0 or 1)
            uint32_t baseOff = ctx.prefixCount;
            // Add opcode length
            if (ctx.opcodeMap == 0) baseOff += 1;
            else if (ctx.opcodeMap == 1) baseOff += 2;
            else if (ctx.opcodeMap == 2 || ctx.opcodeMap == 3) baseOff += 3;
            if (ctx.hasVEX || ctx.hasEVEX) {
                baseOff = ctx.prefixCount + 1; // opcode after VEX prefix
            }
            baseOff += 1; // modrm byte
            if (ctx.hasSIB) baseOff += 1;

            if (dispSz == 1 && baseOff < ctx.bufferLength) {
                disp = SignExtend8(ctx.buffer[baseOff]);
            } else if (dispSz == 2 && baseOff + 1 < ctx.bufferLength) {
                uint16_t v;
                std::memcpy(&v, ctx.buffer + baseOff, 2);
                disp = SignExtend16(v);
            } else if (dispSz == 4 && baseOff + 3 < ctx.bufferLength) {
                uint32_t v;
                std::memcpy(&v, ctx.buffer + baseOff, 4);
                disp = SignExtend32(v);
            }
        }
        BuildMemOperand(rmOp, ctx, disp, rmSizeBits);
    }

    if (regIsDst) {
        operands[0] = regOp;
        operands[1] = rmOp;
    } else {
        operands[0] = rmOp;
        operands[1] = regOp;
    }
    inst.operand_count = 2;
    inst.operand_count_visible = 2;
}

void Decoder::DecodeAccumImm(DecodeContext& ctx,
    DecodedInstruction& inst, DecodedOperand* operands,
    uint16_t sizeBits) noexcept
{
    BuildRegOperand(operands[0], ResolveGPR(0, sizeBits, ctx.hasREX), sizeBits);
    operands[1].type = OperandType::IMMEDIATE;
    operands[1].size = sizeBits;
    inst.operand_count = 2;
    inst.operand_count_visible = 2;
}

void Decoder::DecodeOpcodeReg(DecodeContext& ctx,
    DecodedInstruction& inst, DecodedOperand* operands,
    uint16_t sizeBits) noexcept
{
    uint8_t reg = ctx.opcode & 0x07;
    if (ctx.rexB) reg |= 0x08;
    BuildRegOperand(operands[0], ResolveGPR(reg, sizeBits, ctx.hasREX), sizeBits);
    inst.operand_count = 1;
    inst.operand_count_visible = 1;
}

} // namespace Phantom::Disasm
