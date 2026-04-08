// Copyright (c) ShadowStrike Labs. All rights reserved.
// Licensed under the AGPL-3.0 license. See LICENSE.txt in the project root.
//
// Instruction.hpp — Decoded instruction and operand structures for PhantomDisassembler.
//
// These structs are the native representation that the compatibility layer maps
// Zydis types to. Field names mirror Zydis conventions (operand_count, attributes,
// mem.base, imm.value.u, etc.) to minimize friction during migration.
//
// Layout notes:
//   - Hot fields (mnemonic, length, operand_count, attributes) are grouped at the
//     top of DecodedInstruction to maximise L1-cache locality on decode loops.
//   - DecodedOperand uses an anonymous union zero-initialised via std::memset in its
//     constructor, guaranteeing deterministic state regardless of active member.
//

#pragma once

#include "Types.hpp"

#include <array>
#include <cstdint>
#include <cstring>

namespace Phantom::Disasm {

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of operands stored per decoded instruction.
static constexpr uint8_t MAX_OPERANDS = 4;

/// x86-64 architectural limit on instruction byte length.
static constexpr uint8_t MAX_INSTRUCTION_LENGTH = 15;

// ─────────────────────────────────────────────────────────────────────────────
// Operand sub-structures
// ─────────────────────────────────────────────────────────────────────────────

/// Register operand payload.
struct DecodedOperandReg {
    Register value = Register::NONE;
};

/// Memory operand displacement component.
struct DecodedOperandMemDisp {
    bool     has_displacement = false;
    int64_t  value            = 0;
};

/// Memory operand payload (SIB-style: base + index*scale + disp).
struct DecodedOperandMem {
    Register              segment = Register::NONE;
    Register              base    = Register::NONE;
    Register              index   = Register::NONE;
    uint8_t               scale   = 0;        // 0, 1, 2, 4, or 8
    DecodedOperandMemDisp disp{};
};

/// Far-pointer operand payload (e.g. CALL ptr16:32).
struct DecodedOperandPtr {
    uint16_t segment = 0;
    uint32_t offset  = 0;
};

/// Immediate operand payload.
struct DecodedOperandImm {
    bool is_signed   = false;
    bool is_relative = false;

    union ImmediateValue {
        uint64_t u;
        int64_t  s;
    } value{};
};

// ─────────────────────────────────────────────────────────────────────────────
// DecodedOperand
// ─────────────────────────────────────────────────────────────────────────────

/// A single decoded operand.  Access the type-specific data through the
/// anonymous union members (reg / mem / ptr / imm) after checking `type`.
struct DecodedOperand {
    // ── Identification ──────────────────────────────────────────────────
    uint8_t     id   = 0;
    OperandType type = OperandType::NONE;

    // ── Visibility & action flags (mirrors Zydis operand metadata) ──────
    OperandVisibility visibility = OperandVisibility::INVALID;
    uint8_t           actions    = 0;   // Bitmask of OperandAction flags

    // ── Size in bits (8, 16, 32, 64, 128, 256, 512) ────────────────────
    uint16_t size = 0;

    // ── Type-specific payload ───────────────────────────────────────────
    // Only the member matching `type` is semantically valid after decode.
    // The constructor zero-fills the entire union for deterministic state.
    union {
        DecodedOperandReg reg;
        DecodedOperandMem mem;
        DecodedOperandPtr ptr;
        DecodedOperandImm imm;
    };

    // Zero-initialise every byte, including the anonymous union, so that
    // all members start in a well-defined state regardless of which
    // variant will be populated by the decoder.
    DecodedOperand() noexcept { std::memset(this, 0, sizeof(*this)); }

    // ── Type-query helpers ──────────────────────────────────────────────
    [[nodiscard]] bool IsRegister()  const noexcept { return type == OperandType::REGISTER;  }
    [[nodiscard]] bool IsMemory()    const noexcept { return type == OperandType::MEMORY;    }
    [[nodiscard]] bool IsImmediate() const noexcept { return type == OperandType::IMMEDIATE; }
    [[nodiscard]] bool IsPointer()   const noexcept { return type == OperandType::POINTER;   }

    // ── Action-query helpers ────────────────────────────────────────────
    [[nodiscard]] bool IsRead()    const noexcept { return (actions & OPERAND_ACTION_READ)  != 0; }
    [[nodiscard]] bool IsWrite()   const noexcept { return (actions & OPERAND_ACTION_WRITE) != 0; }
};

// ─────────────────────────────────────────────────────────────────────────────
// DecodedInstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Full decoded x86-64 instruction.
///
/// Field order is chosen for cache efficiency: the fields most frequently
/// touched in hot decode/analysis loops (mnemonic, length, operand_count,
/// attributes) occupy the first cache line.
struct DecodedInstruction {
    // ══════════════════════════════════════════════════════════════════════
    //  HOT — first cache line (most-accessed in analysis loops)
    // ══════════════════════════════════════════════════════════════════════

    /// Instruction mnemonic (e.g. Mnemonic::MOV, Mnemonic::CALL).
    Mnemonic mnemonic = Mnemonic::UNKNOWN;

    /// Encoded instruction length in bytes [1, 15].
    uint8_t length = 0;

    /// Total operand count (explicit + implicit + hidden).
    uint8_t operand_count = 0;

    /// Visible operand count (explicit + implicit, excludes hidden).
    uint8_t operand_count_visible = 0;

    /// Effective operand width in bits (16, 32, or 64).
    uint16_t operand_width = 0;

    /// Effective address width in bits (16, 32, or 64).
    uint16_t address_width = 0;

    /// Instruction attribute bitfield (see ATTRIB_* constants in Types.hpp).
    uint64_t attributes = 0;

    /// Runtime virtual address at which this instruction resides.
    uint64_t address = 0;

    // ══════════════════════════════════════════════════════════════════════
    //  Classification
    // ══════════════════════════════════════════════════════════════════════

    /// High-level instruction category (data transfer, branch, system, …).
    InstructionCategory category = InstructionCategory::UNKNOWN;

    /// ISA extension that introduced this instruction (BASE, SSE, AVX, …).
    ISAExtension isa_ext = ISAExtension::BASE;

    // ══════════════════════════════════════════════════════════════════════
    //  Raw encoding details
    // ══════════════════════════════════════════════════════════════════════

    /// Opcode map: 0 = one-byte, 1 = 0F, 2 = 0F38, 3 = 0F3A.
    uint8_t opcode_map = 0;

    /// Primary opcode byte.
    uint8_t opcode = 0;

    /// ModRM.reg extension (opcode group).
    uint8_t opcode_ext = 0;

    /// Raw ModRM byte (valid only when has_modrm == true).
    uint8_t modrm = 0;

    /// Raw SIB byte (valid only when has_sib == true).
    uint8_t sib = 0;

    /// Whether the instruction encoding contains a ModRM byte.
    bool has_modrm = false;

    /// Whether the instruction encoding contains a SIB byte.
    bool has_sib = false;

    // ══════════════════════════════════════════════════════════════════════
    //  Raw instruction bytes
    // ══════════════════════════════════════════════════════════════════════

    /// Copy of the raw encoded bytes (length valid bytes, rest zeroed).
    std::array<uint8_t, MAX_INSTRUCTION_LENGTH> raw_bytes{};

    // ══════════════════════════════════════════════════════════════════════
    //  VEX / EVEX encoding info
    // ══════════════════════════════════════════════════════════════════════

    struct VectorEncoding {
        bool    has_vex   = false;
        bool    has_evex  = false;

        // VEX fields
        uint8_t vex_l     = 0;    // Vector length (0 = 128, 1 = 256)
        uint8_t vex_pp    = 0;    // Implied mandatory prefix
        uint8_t vex_vvvv  = 0;    // Additional register specifier
        bool    vex_w     = false; // Operand-size promotion

        // EVEX-specific fields
        uint8_t evex_z    = 0;    // Zeroing-masking flag
        uint8_t evex_ll   = 0;    // Vector length (EVEX, 0/1/2)
        uint8_t evex_b    = 0;    // Broadcast / embedded rounding / SAE
        uint8_t evex_aaa  = 0;    // Opmask register index (k0-k7)
    } encoding{};

    // ══════════════════════════════════════════════════════════════════════
    //  Segment override
    // ══════════════════════════════════════════════════════════════════════

    /// Active segment override prefix, if any.
    Register segment_override = Register::NONE;

    // ══════════════════════════════════════════════════════════════════════
    //  Convenience helpers
    // ══════════════════════════════════════════════════════════════════════

    /// Reset every field to its default-initialised state.
    void Clear() noexcept { *this = DecodedInstruction{}; }

    /// Address of the byte immediately following this instruction.
    [[nodiscard]] uint64_t NextAddress() const noexcept {
        return address + length;
    }

    /// Test a single attribute bit.
    [[nodiscard]] bool HasAttribute(uint64_t attr) const noexcept {
        return (attributes & attr) != 0;
    }

    /// True for any branch / call / return / interrupt instruction.
    [[nodiscard]] bool IsControlFlow() const noexcept {
        return category == InstructionCategory::CONTROL_FLOW ||
               category == InstructionCategory::BRANCH       ||
               category == InstructionCategory::CALL         ||
               category == InstructionCategory::RET          ||
               category == InstructionCategory::CONDITIONAL;
    }

    /// True if the instruction requires CPL 0 (ring-0).
    [[nodiscard]] bool IsPrivileged() const noexcept {
        return HasAttribute(ATTRIB_IS_PRIVILEGED);
    }

    /// True if a LOCK prefix is present.
    [[nodiscard]] bool HasLock() const noexcept {
        return HasAttribute(ATTRIB_HAS_LOCK);
    }

    /// True if a REP / REPE / REPNE prefix is present.
    [[nodiscard]] bool HasRep() const noexcept {
        return HasAttribute(ATTRIB_HAS_REP)   ||
               HasAttribute(ATTRIB_HAS_REPE)  ||
               HasAttribute(ATTRIB_HAS_REPNE);
    }

    /// True if the instruction carries a VEX or EVEX encoding.
    [[nodiscard]] bool IsVectorEncoded() const noexcept {
        return encoding.has_vex || encoding.has_evex;
    }

    /// True if the instruction is a NOP (explicit or multi-byte).
    [[nodiscard]] bool IsNop() const noexcept {
        return category == InstructionCategory::NOP;
    }

    /// True if the instruction accesses the stack pointer implicitly
    /// (PUSH, POP, CALL, RET, ENTER, LEAVE, INT, IRET, …).
    [[nodiscard]] bool IsStackOperation() const noexcept {
        return category == InstructionCategory::PUSH  ||
               category == InstructionCategory::POP   ||
               category == InstructionCategory::CALL  ||
               category == InstructionCategory::RET;
    }

    /// True if the instruction is a system-level instruction
    /// (SYSCALL, SYSENTER, SYSRET, INT, CPUID, RDMSR, WRMSR, …).
    [[nodiscard]] bool IsSystem() const noexcept {
        return category == InstructionCategory::SYSTEM ||
               category == InstructionCategory::SYSCALL;
    }
};

} // namespace Phantom::Disasm
