/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "Instruction.hpp"
#include "../State/CPUState.hpp"
#include "../../Common/Errors.hpp"
#include <cstdint>
#include <optional>
#include <span>

namespace Phantom {

// ============================================================================
// x86/x64 Instruction Decoder
// ============================================================================
// Decodes raw instruction bytes into a DecodedInstruction struct.
//
// The decoder implements the full x86/x64 instruction encoding:
//   1. Legacy prefixes (up to 4 groups)
//   2. REX prefix (64-bit mode)
//   3. Opcode (1, 2, or 3 bytes)
//   4. ModR/M byte (if required)
//   5. SIB byte (if required)
//   6. Displacement (0, 1, 2, or 4 bytes)
//   7. Immediate (0, 1, 2, 4, or 8 bytes)
//
// Design: Stateless decoder. CPU mode is passed per-call.
// No heap allocation. No exceptions in hot path — returns ErrorCode.

class InstructionDecoder {
public:
    InstructionDecoder() noexcept = default;

    // Decode a single instruction from the byte stream.
    // Returns the number of bytes consumed, or an error.
    // `bytes` must contain at least 15 bytes (kMaxInstructionLength) OR up to
    // the end of the mapped page. The decoder will not read beyond `bytes.size()`.
    [[nodiscard]] ErrorCode Decode(
        std::span<const uint8_t> bytes,
        GuestAddress rip,
        CPUMode mode,
        DecodedInstruction& out) noexcept;

private:
    // === Decode phases ===

    // Phase 1: Consume all legacy prefixes and REX prefix
    ErrorCode DecodePrefixes(
        std::span<const uint8_t> bytes,
        CPUMode mode,
        InstructionPrefixes& prefixes,
        uint32_t& offset) noexcept;

    // Phase 1b: Decode VEX prefix (C4/C5) if present
    ErrorCode DecodeVEX(
        std::span<const uint8_t> bytes,
        CPUMode mode,
        InstructionPrefixes& prefixes,
        uint32_t& offset) noexcept;

    // Phase 1c: Decode EVEX prefix (62h) if present
    ErrorCode DecodeEVEX(
        std::span<const uint8_t> bytes,
        CPUMode mode,
        InstructionPrefixes& prefixes,
        uint32_t& offset) noexcept;

    // Phase 2: Determine opcode map and primary opcode
    ErrorCode DecodeOpcode(
        std::span<const uint8_t> bytes,
        uint32_t& offset,
        OpcodeMap& map,
        uint8_t& opcode) noexcept;

    // Phase 3: Decode ModR/M byte if present
    ErrorCode DecodeModRM(
        std::span<const uint8_t> bytes,
        uint32_t& offset,
        CPUMode mode,
        const InstructionPrefixes& prefixes,
        DecodedInstruction& inst) noexcept;

    // Phase 4: Decode SIB byte if present
    ErrorCode DecodeSIB(
        std::span<const uint8_t> bytes,
        uint32_t& offset,
        CPUMode mode,
        const InstructionPrefixes& prefixes,
        DecodedInstruction& inst) noexcept;

    // Phase 5: Read displacement bytes
    ErrorCode DecodeDisplacement(
        std::span<const uint8_t> bytes,
        uint32_t& offset,
        uint8_t dispSize,
        DecodedInstruction& inst) noexcept;

    // Phase 6: Read immediate bytes
    ErrorCode DecodeImmediate(
        std::span<const uint8_t> bytes,
        uint32_t& offset,
        uint8_t immSize,
        DecodedInstruction& inst) noexcept;

    // === Operand decode helpers ===

    // Build register operand
    void BuildRegOperand(
        DecodedOperand& op,
        RegType regType,
        uint8_t index,
        OperandSize size,
        bool isHighByte = false) noexcept;

    // Build memory operand from ModRM/SIB
    void BuildMemOperand(
        DecodedOperand& op,
        const DecodedInstruction& inst,
        CPUMode mode,
        const InstructionPrefixes& prefixes) noexcept;

    // Build immediate operand
    void BuildImmOperand(
        DecodedOperand& op,
        int64_t value,
        OperandSize size,
        bool isSigned) noexcept;

    // Build relative offset operand
    void BuildRelOperand(
        DecodedOperand& op,
        int64_t offset,
        OperandSize size) noexcept;

    // === Opcode classification helpers ===

    // Determine if an opcode requires a ModR/M byte
    [[nodiscard]] bool OpcodeRequiresModRM(OpcodeMap map, uint8_t opcode) const noexcept;

    // Determine immediate size for an opcode
    [[nodiscard]] uint8_t OpcodeImmediateSize(
        OpcodeMap map,
        uint8_t opcode,
        OperandSize opSize) const noexcept;

    // Determine the default segment for a memory operand
    [[nodiscard]] SegReg DefaultSegment(uint8_t baseReg) const noexcept;

    // === Opcode decode functions (populate operands for specific instruction forms) ===

    // Standard ModRM r/m, reg encoding (most ALU ops)
    void DecodeModRMOperands(
        DecodedInstruction& inst,
        OperandSize regSize,
        OperandSize rmSize,
        bool regIsDst) noexcept;

    // AL/AX/EAX/RAX, imm encoding (short forms)
    void DecodeAccumImm(
        DecodedInstruction& inst,
        OperandSize size) noexcept;

    // Register encoded in low 3 bits of opcode
    void DecodeOpcodeReg(
        DecodedInstruction& inst,
        uint8_t opcode,
        OperandSize size,
        const InstructionPrefixes& prefixes) noexcept;

    // Read raw bytes from the stream with bounds checking
    [[nodiscard]] bool ReadByte(
        std::span<const uint8_t> bytes,
        uint32_t offset,
        uint8_t& out) const noexcept;

    [[nodiscard]] bool ReadWord(
        std::span<const uint8_t> bytes,
        uint32_t offset,
        uint16_t& out) const noexcept;

    [[nodiscard]] bool ReadDword(
        std::span<const uint8_t> bytes,
        uint32_t offset,
        uint32_t& out) const noexcept;

    [[nodiscard]] bool ReadQword(
        std::span<const uint8_t> bytes,
        uint32_t offset,
        uint64_t& out) const noexcept;

    // Sign-extend helpers
    [[nodiscard]] static int64_t SignExtend8(uint8_t v) noexcept {
        return static_cast<int64_t>(static_cast<int8_t>(v));
    }
    [[nodiscard]] static int64_t SignExtend16(uint16_t v) noexcept {
        return static_cast<int64_t>(static_cast<int16_t>(v));
    }
    [[nodiscard]] static int64_t SignExtend32(uint32_t v) noexcept {
        return static_cast<int64_t>(static_cast<int32_t>(v));
    }
};

} // namespace Phantom
