/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Constants.hpp"
#include <cstdint>
#include <array>

namespace Phantom {

// ============================================================================
// Opcode Identifier
// ============================================================================
// Canonicalized opcode for dispatch. Encodes:
//   - Map (1-byte, 0F, 0F38, 0F3A)
//   - Primary opcode byte
//   - ModRM.reg extension (for group opcodes)

enum class OpcodeMap : uint8_t {
    OneByte  = 0,     // No escape prefix
    TwoByte  = 1,     // 0F xx
    ThreeByte38 = 2,  // 0F 38 xx
    ThreeByte3A = 3,  // 0F 3A xx
};

// ============================================================================
// Operand Type
// ============================================================================

enum class OperandType : uint8_t {
    None,
    Register,         // GPR, segment, control, debug, FPU, XMM
    Memory,           // [base + index*scale + disp]
    Immediate,        // Literal value embedded in instruction
    RelativeOffset,   // Relative branch target (Jcc, CALL rel)
    FarPointer,       // seg:offset (CALL FAR, JMP FAR)
    ImplicitReg,      // Register implied by opcode (e.g., RAX for MUL)
};

// ============================================================================
// Register Type
// ============================================================================

enum class RegType : uint8_t {
    GPR,
    Segment,
    Control,
    Debug,
    FPU,         // x87 ST(i)
    XMM,         // SSE XMM0-XMM15
    YMM,         // AVX YMM0-YMM15 (256-bit)
    Flags,       // RFLAGS
    IP,          // RIP
};

// ============================================================================
// Decoded Operand
// ============================================================================

struct DecodedOperand {
    OperandType type = OperandType::None;
    OperandSize size = OperandSize::Size32;

    union {
        struct {
            RegType  regType;
            uint8_t  regIndex;
            bool     isHighByte;   // AH, CH, DH, BH
        } reg;

        struct {
            uint8_t   baseReg;     // GPR index (0-15), 0xFF = none
            uint8_t   indexReg;    // GPR index (0-15), 0xFF = none
            uint8_t   scale;       // 1, 2, 4, 8
            int64_t   displacement;
            SegReg    segment;     // Segment override (default DS/SS)
            bool      hasBase;
            bool      hasIndex;
            bool      ripRelative; // RIP-relative addressing (64-bit)
        } mem;

        struct {
            uint64_t  value;
            bool      isSigned;    // True if sign-extended
        } imm;

        struct {
            int64_t   offset;      // Signed offset from next instruction
        } rel;
    };

    DecodedOperand() noexcept { std::memset(this, 0, sizeof(*this)); }

    [[nodiscard]] bool IsRegister() const noexcept { return type == OperandType::Register; }
    [[nodiscard]] bool IsMemory() const noexcept { return type == OperandType::Memory; }
    [[nodiscard]] bool IsImmediate() const noexcept { return type == OperandType::Immediate; }
    [[nodiscard]] bool IsRelative() const noexcept { return type == OperandType::RelativeOffset; }
};

// ============================================================================
// Instruction Prefixes
// ============================================================================

struct InstructionPrefixes {
    // Group 1: Lock / Rep
    bool hasLock      = false;
    bool hasRep       = false;    // F3 (REP / REPE)
    bool hasRepNE     = false;    // F2 (REPNE)

    // Group 2: Segment override
    bool hasSegOverride = false;
    SegReg segOverride  = SegReg::DS;

    // Group 3: Operand size override (66h)
    bool hasOpSizeOverride = false;

    // Group 4: Address size override (67h)
    bool hasAddrSizeOverride = false;

    // REX prefix (64-bit mode only)
    bool hasREX   = false;
    bool rexW     = false;     // 64-bit operand size
    bool rexR     = false;     // ModRM.reg extension
    bool rexX     = false;     // SIB.index extension
    bool rexB     = false;     // ModRM.rm / SIB.base extension

    // VEX prefix (2-byte C5 or 3-byte C4)
    bool hasVEX      = false;
    uint8_t vexL     = 0;      // Vector length: 0=128-bit (XMM), 1=256-bit (YMM)
    uint8_t vexPP    = 0;      // Implied prefix: 0=none, 1=66, 2=F3, 3=F2
    uint8_t vexMMMMM = 1;      // Opcode map: 1=0F, 2=0F38, 3=0F3A
    uint8_t vexVVVV  = 0;      // Additional register operand (inverted, 0-15)
    bool    vexW     = false;   // Like REX.W for VEX-encoded instructions

    // Total prefix byte count (for instruction length calculation)
    uint8_t prefixCount = 0;

    [[nodiscard]] OperandSize EffectiveOperandSize(CPUMode mode) const noexcept {
        if (mode == CPUMode::Long64) {
            if (rexW) return OperandSize::Size64;
            if (hasOpSizeOverride) return OperandSize::Size16;
            return OperandSize::Size32;
        }
        if (mode == CPUMode::Protected32) {
            if (hasOpSizeOverride) return OperandSize::Size16;
            return OperandSize::Size32;
        }
        // Real16
        if (hasOpSizeOverride) return OperandSize::Size32;
        return OperandSize::Size16;
    }

    [[nodiscard]] AddressSize EffectiveAddressSize(CPUMode mode) const noexcept {
        if (mode == CPUMode::Long64) {
            if (hasAddrSizeOverride) return AddressSize::Addr32;
            return AddressSize::Addr64;
        }
        if (mode == CPUMode::Protected32) {
            if (hasAddrSizeOverride) return AddressSize::Addr16;
            return AddressSize::Addr32;
        }
        if (hasAddrSizeOverride) return AddressSize::Addr32;
        return AddressSize::Addr16;
    }
};

// ============================================================================
// Decoded Instruction
// ============================================================================
// This is what the decoder produces and the executor consumes.
// Must be compact for cache efficiency (target: ≤128 bytes).

struct DecodedInstruction {
    // Opcode identification
    OpcodeMap    opcodeMap   = OpcodeMap::OneByte;
    uint8_t      opcode      = 0;      // Primary opcode byte
    uint8_t      opcodeExt   = 0;      // ModRM.reg extension for group opcodes

    // Prefixes
    InstructionPrefixes prefixes;

    // Operands (max 3: dst, src1, src2)
    std::array<DecodedOperand, 3> operands;
    uint8_t operandCount = 0;

    // Effective sizes (resolved from prefixes + mode)
    OperandSize  operandSize = OperandSize::Size32;
    AddressSize  addressSize = AddressSize::Addr64;

    // Raw bytes
    uint8_t      length      = 0;      // Total instruction length in bytes
    GuestAddress address     = 0;      // RIP where this instruction starts

    // ModRM/SIB (raw, for executor reference)
    uint8_t      modrm       = 0;
    uint8_t      sib         = 0;
    bool         hasModRM    = false;
    bool         hasSIB      = false;

    // Immediate value (raw, sign-extended to 64-bit)
    int64_t      immediate   = 0;
    uint8_t      immSize     = 0;      // Immediate byte count (1, 2, 4, 8)

    // Displacement (raw, sign-extended)
    int64_t      displacement = 0;
    uint8_t      dispSize     = 0;     // Displacement byte count (0, 1, 2, 4)

    void Clear() noexcept {
        *this = DecodedInstruction{};
    }

    [[nodiscard]] const DecodedOperand& Op(uint8_t i) const noexcept {
        return operands[i];
    }
    [[nodiscard]] DecodedOperand& Op(uint8_t i) noexcept {
        return operands[i];
    }

    [[nodiscard]] GuestAddress NextRIP() const noexcept {
        return address + length;
    }
};

} // namespace Phantom
